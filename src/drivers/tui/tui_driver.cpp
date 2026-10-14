#include "drivers/tui/tui_driver.hpp"
#include "../../include/pkg/user.hpp"

#include <chrono>
#include <thread>

using namespace ftxui;

// ============================================================
// Construction & Destruction
// ============================================================

TUIDriver::TUIDriver(std::shared_ptr<UserClient> user_client)
    : user_client(user_client) {}

TUIDriver::~TUIDriver() {
  is_running.store(false);
  shutdown_cv.notify_all();
  worker_cv.notify_all();
  if (periodic_group_checker_thread.joinable())
    periodic_group_checker_thread.join();
  if (active_group_fetcher_thread.joinable())
    active_group_fetcher_thread.join();
  if (worker_thread.joinable())
    worker_thread.join();
}

// ============================================================
// Public Helpers
// ============================================================

void TUIDriver::add_action(std::string trigger, std::string guide,
                           std::function<void(std::string)> action) {
  actions[trigger] = action;
  guides[trigger] = guide;
}

void TUIDriver::print_status(std::string output) {
  if (!is_running.load())
    return;
  screen.Post([this, output]() { status_text = output; });
  screen.PostEvent(Event::Custom);
}

void TUIDriver::launch_worker(std::function<void()> work) {
  {
    std::lock_guard<std::mutex> lock(worker_mtx);
    work_queue.push(std::move(work));
  }
  worker_cv.notify_one();
}

// Drains queued background tasks one at a time until shutdown. Enqueuing a task
// never spawns a thread, so bursts of actions (e.g. sending many messages fast)
// can't exhaust thread resources.
void TUIDriver::worker_loop() {
  while (true) {
    std::function<void()> task;
    {
      std::unique_lock<std::mutex> lock(worker_mtx);
      worker_cv.wait(
          lock, [this] { return !is_running.load() || !work_queue.empty(); });
      if (!is_running.load() && work_queue.empty())
        return;
      task = std::move(work_queue.front());
      work_queue.pop();
    }
    if (is_running.load()) {
      try {
        task();
      } catch (...) {
        // A failed background task must never take down the worker.
      }
    }
  }
}

// Caller must hold state_mtx.
void TUIDriver::add_server(std::string ip, std::string port,
                           std::vector<std::string> groups) {
  for (size_t i = 0; i < servers.size(); ++i) {
    if (servers[i].ip == ip && servers[i].port == port) {
      servers[i].groups = groups;
      servers[i].is_authenticated = true;
      if (selected_server == (int)i) {
        refresh_groups();
      }
      return;
    }
  }
  servers.push_back({ip, port, groups, true});
  server_names.push_back(ip + ":" + port);
  if (selected_server == -1) {
    selected_server = (int)servers.size() - 1;
    refresh_groups();
  }
}

// Caller must hold state_mtx.
void TUIDriver::refresh_groups() {
  current_groups.clear();
  if (selected_server >= 0 && selected_server < (int)servers.size()) {
    current_groups = servers[selected_server].groups;
  }
  selected_group = -1;
  messages.clear();
}

// ============================================================
// Background Polling Threads
// ============================================================

void TUIDriver::start_periodic_group_checker() {
  periodic_group_checker_thread = std::thread([this]() {
    while (is_running.load()) {
      std::unique_lock<std::mutex> sleep_lock(shutdown_mtx);
      if (shutdown_cv.wait_for(sleep_lock, std::chrono::seconds(10),
                               [this] { return !is_running.load(); }))
        return;
      sleep_lock.unlock();

      // Snapshot the authenticated servers under the lock, then release it
      // before any network work.
      std::vector<std::pair<std::string, std::string>> targets; // (ip, port)
      {
        std::lock_guard<std::mutex> lk(state_mtx);
        for (const auto &s : servers)
          if (s.is_authenticated)
            targets.push_back({s.ip, s.port});
      }

      for (const auto &[ip, port] : targets) {
        int port_num = 0;
        try {
          port_num = std::stoi(port);
        } catch (...) {
          continue;
        }
        std::vector<std::string> groups;
        try {
          groups = user_client->check_group_pertenece(ip, port_num);
        } catch (...) {
          continue;
        }
        if (groups.empty())
          continue;

        // Match the server by its (ip, port) key — an index could be stale.
        if (!is_running.load())
          return;
        screen.Post([this, ip, port, groups]() {
          std::lock_guard<std::mutex> lk(state_mtx);
          for (size_t i = 0; i < servers.size(); ++i) {
            if (servers[i].ip == ip && servers[i].port == port) {
              servers[i].groups = groups;
              if (selected_server == (int)i)
                current_groups = groups;
              break;
            }
          }
        });
        screen.PostEvent(Event::Custom);
      }
    }
  });
}

void TUIDriver::start_active_group_message_fetcher() {
  active_group_fetcher_thread = std::thread([this]() {
    while (is_running.load()) {
      std::unique_lock<std::mutex> sleep_lock(shutdown_mtx);
      if (shutdown_cv.wait_for(sleep_lock, std::chrono::milliseconds(500),
                               [this] { return !is_running.load(); }))
        return;
      sleep_lock.unlock();

      // Snapshot the active selection under the lock, then release it.
      std::string ip, port, group_id;
      bool have = false;
      {
        std::lock_guard<std::mutex> lk(state_mtx);
        if (selected_server >= 0 && selected_server < (int)servers.size() &&
            selected_group >= 0 &&
            selected_group < (int)current_groups.size()) {
          ip = servers[selected_server].ip;
          port = servers[selected_server].port;
          group_id = current_groups[selected_group];
          have = true;
        }
      }
      if (!have)
        continue;

      int port_num = 0;
      try {
        port_num = std::stoi(port);
      } catch (...) {
        continue;
      }

      std::vector<std::pair<std::string, std::string>> fetched;
      try {
        fetched =
            user_client->FetchGroupMessagesStructured(ip, port_num, group_id);
      } catch (...) {
        continue;
      }
      if (fetched.empty())
        continue;

      std::vector<ChatMessage> updated_list;
      for (const auto &[sender, text] : fetched)
        updated_list.push_back({sender, text});

      std::string key = ip + ":" + port + "/" + group_id;
      if (!is_running.load())
        return;
      screen.Post([this, key, ip, port, group_id, updated_list]() {
        std::lock_guard<std::mutex> lk(state_mtx);
        // Apply only if this is still the active group.
        if (selected_server < 0 || selected_server >= (int)servers.size() ||
            selected_group < 0 ||
            selected_group >= (int)current_groups.size() ||
            servers[selected_server].ip != ip ||
            servers[selected_server].port != port ||
            current_groups[selected_group] != group_id)
          return;

        // Compare by content, not just size (size can coincide across changes).
        const auto &existing = chat_history[key];
        bool changed = existing.size() != updated_list.size();
        for (size_t i = 0; !changed && i < updated_list.size(); ++i)
          if (existing[i].sender != updated_list[i].sender ||
              existing[i].text != updated_list[i].text)
            changed = true;
        if (changed) {
          chat_history[key] = updated_list;
          messages = updated_list;
          screen.PostEvent(Event::Custom);
        }
      });
    }
  });
}

// ============================================================
// Main TUI loop
// ============================================================

void TUIDriver::run() {
  worker_thread = std::thread(&TUIDriver::worker_loop, this);
  start_periodic_group_checker();
  start_active_group_message_fetcher();

  // ==========================================================
  //  SIDEBAR – SERVERS
  // ==========================================================

  MenuOption server_menu_opt;
  server_menu_opt.on_change = [&] {
    std::lock_guard<std::mutex> lk(state_mtx);
    refresh_groups();
  };
  auto server_menu = Menu(&server_names, &selected_server, server_menu_opt);

  // -- Add Server form --
  auto add_btn = Button(
      " + Add Server ",
      [&] {
        show_add_form = true;
        show_create_group_form = false;
      },
      ButtonOption::Animated(Color::Cyan));

  auto ip_input = Input(&new_ip, "IP address");
  auto port_input = Input(&new_port, "Port");

  std::vector<std::string> auth_entries = {"Login", "Register"};
  auto auth_radio = Radiobox(&auth_entries, &auth_mode);

  auto connect_btn = Button(
      "Connect",
      [&] {
        if (new_ip.empty() || new_port.empty())
          return;

        std::string ip = new_ip;
        std::string port = new_port;
        int mode = auth_mode;

        show_add_form = false;
        new_ip.clear();
        new_port.clear();
        status_text = "Connecting to " + ip + ":" + port + "...";

        launch_worker([this, ip, port, mode]() {
          bool ok = false;
          std::vector<std::string> fetched_groups;

          try {
            std::string cmd =
                (mode == 0 ? "login " : "register ") + ip + " " + port;
            // HandleLoginOrRegister returns false (not throws) on failure.
            ok = user_client->HandleLoginOrRegister(cmd);
            if (ok) {
              int port_num = std::stoi(port);
              fetched_groups = user_client->check_group_pertenece(ip, port_num);
            }
          } catch (...) {
            ok = false;
          }

          screen.Post([this, ip, port, mode, ok, fetched_groups]() {
            std::lock_guard<std::mutex> lk(state_mtx);
            if (ok) {
              // add_server marks the entry authenticated; only do so on
              // success.
              add_server(ip, port, fetched_groups);
              status_text = "Connected to " + ip + ":" + port;
            } else {
              status_text = std::string(mode == 0 ? "Login" : "Registration") +
                            " failed for " + ip + ":" + port +
                            " — check credentials and that the server is up.";
            }
          });
          screen.PostEvent(Event::Custom);
        });
      },
      ButtonOption::Animated(Color::Green));

  auto cancel_add_btn = Button(
      "Cancel",
      [&] {
        new_ip.clear();
        new_port.clear();
        show_add_form = false;
      },
      ButtonOption::Animated(Color::Red));

  auto add_form_buttons = Container::Horizontal({connect_btn, cancel_add_btn});
  auto add_form =
      Container::Vertical({ip_input, port_input, auth_radio, add_form_buttons});

  auto add_btn_maybe = Maybe(add_btn, [&] { return !show_add_form; });
  auto add_form_maybe = Maybe(add_form, [&] { return show_add_form; });
  auto add_section = Container::Vertical({add_btn_maybe, add_form_maybe});

  // ==========================================================
  //  SIDEBAR – GROUPS & CREATE GROUP FORM
  // ==========================================================

  auto user_checkboxes_container = Container::Vertical({});

  auto create_group_btn = Button(
      " + Create Group ",
      [&] {
        if (selected_server < 0 || selected_server >= (int)servers.size()) {
          status_text = "Select a server first to create a group!";
          return;
        }
        std::string ip = servers[selected_server].ip;
        int port_num = 0;
        try {
          port_num = std::stoi(servers[selected_server].port);
        } catch (...) {
          status_text = "Invalid port for the selected server.";
          return;
        }
        status_text = "Fetching registered users...";

        launch_worker([this, ip, port_num, user_checkboxes_container]() {
          auto reg_users = user_client->get_registered_users(ip, port_num);
          std::string my_id = user_client->get_id();

          screen.Post([this, reg_users, my_id, user_checkboxes_container]() {
            registered_users_selection.clear();
            user_checkboxes_container->DetachAllChildren();

            for (const auto &u : reg_users) {
              if (u == my_id)
                continue; // Exclude own ID from list
              registered_users_selection.push_back({u, false});
            }

            for (size_t i = 0; i < registered_users_selection.size(); ++i) {
              user_checkboxes_container->Add(
                  Checkbox(&registered_users_selection[i].name,
                           &registered_users_selection[i].selected));
            }

            show_create_group_form = true;
            show_add_form = false;
            status_text = "Select members for new group...";
          });
          screen.PostEvent(Event::Custom);
        });
      },
      ButtonOption::Animated(Color::Yellow));

  auto group_id_input =
      Input(&new_group_id, "Group ID (no spaces, e.g. #secret)");

  auto submit_create_group_btn = Button(
      "Create",
      [&] {
        if (new_group_id.empty())
          return;
        if (selected_server < 0 || selected_server >= (int)servers.size())
          return;

        std::string ip = servers[selected_server].ip;
        std::string port = servers[selected_server].port;
        std::string gid = new_group_id;

        // Build member list from selected checkboxes + manual input
        std::vector<std::string> selected_members;
        for (const auto &item : registered_users_selection) {
          if (item.selected) {
            selected_members.push_back(item.name);
          }
        }

        std::string members_str;
        for (size_t i = 0; i < selected_members.size(); ++i) {
          members_str += selected_members[i];
          if (i + 1 < selected_members.size())
            members_str += ",";
        }

        show_create_group_form = false;
        new_group_id.clear();
        status_text = "Creating group " + gid + "...";

        launch_worker([this, ip, port, gid, members_str]() {
          try {
            std::string cmd = "group-create " + ip + " " + port + " " + gid +
                              " " + members_str;
            bool success = user_client->HandleGroupCreate(cmd);

            if (success) {
              int port_num = std::stoi(port);
              std::vector<std::string> updated_groups =
                  user_client->check_group_pertenece(ip, port_num);

              screen.Post([this, updated_groups, gid]() {
                std::lock_guard<std::mutex> lk(state_mtx);
                if (selected_server >= 0 &&
                    selected_server < (int)servers.size()) {
                  servers[selected_server].groups = updated_groups;
                  refresh_groups();
                }
                status_text = "Group " + gid + " created successfully!";
              });
            } else {
              screen.Post([this, gid]() {
                status_text = "Group creation failed for " + gid +
                              ". Check escrow keygen status.";
              });
            }
          } catch (const std::exception &e) {
            std::string err_msg = e.what();
            screen.Post([this, err_msg]() {
              status_text = "Group creation failed: " + err_msg;
            });
          }
          screen.PostEvent(Event::Custom);
        });
      },
      ButtonOption::Animated(Color::Green));

  auto cancel_create_group_btn = Button(
      "Cancel",
      [&] {
        new_group_id.clear();
        show_create_group_form = false;
      },
      ButtonOption::Animated(Color::Red));

  auto create_form_buttons =
      Container::Horizontal({submit_create_group_btn, cancel_create_group_btn});
  auto create_group_form = Container::Vertical(
      {group_id_input, user_checkboxes_container, create_form_buttons});

  auto create_group_btn_maybe =
      Maybe(create_group_btn, [&] { return !show_create_group_form; });
  auto create_group_form_maybe =
      Maybe(create_group_form, [&] { return show_create_group_form; });

  // -- Group menu --
  MenuOption group_menu_opt;
  group_menu_opt.on_change = [&] {
    std::lock_guard<std::mutex> lk(state_mtx);
    if (selected_server >= 0 && selected_server < (int)servers.size() &&
        selected_group >= 0 && selected_group < (int)current_groups.size()) {
      std::string key = servers[selected_server].ip + ":" +
                        servers[selected_server].port + "/" +
                        current_groups[selected_group];
      messages = chat_history[key];
    }
  };
  auto group_menu = Menu(&current_groups, &selected_group, group_menu_opt);

  auto sidebar = Container::Vertical({
      server_menu,
      add_section,
      create_group_btn_maybe,
      create_group_form_maybe,
      group_menu,
  });

  // ==========================================================
  //  CHAT PANEL  – message history + input field
  // ==========================================================

  InputOption chat_opt;
  chat_opt.on_enter = [&] {
    if (chat_input_text.empty())
      return;

    std::string msg = chat_input_text;
    chat_input_text.clear();

    std::string cmd;
    {
      std::lock_guard<std::mutex> lk(state_mtx);
      std::string my_id = user_client->get_id();
      std::string sender_name = my_id.empty() ? "You" : my_id;
      messages.push_back({sender_name, msg});

      if (selected_server >= 0 && selected_server < (int)servers.size() &&
          selected_group >= 0 && selected_group < (int)current_groups.size()) {
        std::string ip = servers[selected_server].ip;
        std::string port = servers[selected_server].port;
        std::string group_id = current_groups[selected_group];
        std::string key = ip + ":" + port + "/" + group_id;
        chat_history[key] = messages;
        cmd = "group-send " + ip + " " + port + " " + group_id + " " + msg;
      }
    }

    // Send outside the lock (network work must not hold the UI-state mutex).
    if (!cmd.empty()) {
      launch_worker([this, cmd]() {
        try {
          user_client->HandleGroupSend(cmd);
        } catch (...) {
        }
      });
    }
  };
  auto chat_input = Input(&chat_input_text, "Type a message...", chat_opt);
  auto chat_panel = Container::Vertical({chat_input});

  auto main_container = Container::Horizontal({sidebar, chat_panel});

  // ==========================================================
  //  RENDERER  – Visual Layout
  // ==========================================================

  auto renderer = Renderer(main_container, [&] {
    std::string group_title = "No group selected";
    bool active_selection = false;

    if (selected_server >= 0 && selected_server < (int)servers.size() &&
        selected_group >= 0 && selected_group < (int)current_groups.size()) {
      group_title = current_groups[selected_group] + "  @  " +
                    server_names[selected_server];
      active_selection = true;
    }

    // -- Build chat message elements --
    Elements msg_elements;
    std::string my_id = user_client->get_id();

    if (!active_selection) {
      msg_elements.push_back(
          vbox({
              text(" welcome to Project Accountability ") | center | bold |
                  color(Color::Cyan),
              text(""),
              text("No server or group selected.") | center | dim,
              text("Select a server and group from the left sidebar to start "
                   "chatting.") |
                  center | dim,
          }) |
          center | flex);
    } else {
      for (const auto &m : messages) {
        bool is_me = (m.sender == "You" || m.sender == my_id);
        if (is_me) {
          msg_elements.push_back(hbox({
              filler(),
              vbox({
                  text("[" + m.sender + "]") | bold | color(Color::Yellow) |
                      align_right,
                  paragraphAlignRight(m.text),
              }) | borderLight |
                  color(Color::Green) | size(WIDTH, LESS_THAN, 60),
          }));
        } else {
          msg_elements.push_back(hbox({
              vbox({
                  text("[" + m.sender + "]") | bold | color(Color::Cyan),
                  paragraphAlignLeft(m.text),
              }) | borderLight |
                  color(Color::Cyan) | size(WIDTH, LESS_THAN, 60),
              filler(),
          }));
        }
      }
      if (messages.empty()) {
        msg_elements.push_back(text("  No messages in this group yet. Type "
                                    "below to send a message!") |
                               dim);
      }
      msg_elements.push_back(text("") | focus);
    }

    // -- Build add-server form visual --
    Element add_section_el;
    if (show_add_form) {
      add_section_el = vbox({
                           text("  IP:") | dim,
                           ip_input->Render() | borderLight,
                           text("  Port:") | dim,
                           port_input->Render() | borderLight,
                           text("  Mode:") | dim,
                           auth_radio->Render(),
                           hbox({
                               connect_btn->Render(),
                               text(" "),
                               cancel_add_btn->Render(),
                           }) | center,
                       }) |
                       border;
    } else {
      add_section_el = add_btn->Render() | center;
    }

    // -- Build create-group form visual --
    Element create_group_section_el;
    if (show_create_group_form) {
      create_group_section_el =
          vbox({
              text("  Group ID:") | dim,
              group_id_input->Render() | borderLight,
              text("  Registered Users:") | dim,
              user_checkboxes_container->Render() | borderLight |
                  size(HEIGHT, LESS_THAN, 6),
              hbox({
                  submit_create_group_btn->Render(),
                  text(" "),
                  cancel_create_group_btn->Render(),
              }) | center,
          }) |
          border;
    } else {
      create_group_section_el = create_group_btn->Render() | center;
    }

    // Sidebar visual
    auto sidebar_el = vbox({
        text(" SERVERS") | bold | color(Color::Cyan),
        separator(),
        server_menu->Render() | vscroll_indicator | yframe |
            size(HEIGHT, LESS_THAN, 8),
        separator(),
        add_section_el,
        separator(),
        text(" GROUPS") | bold | color(Color::Yellow),
        separator(),
        create_group_section_el,
        separator(),
        group_menu->Render() | vscroll_indicator | yframe | flex,
    });

    // Right chat panel visual
    auto chat_el = vbox({
        text(" " + group_title) | bold | color(Color::Green),
        separator(),
        vbox(msg_elements) | vscroll_indicator | yframe | flex,
        separator(),
        hbox({
            text(" > ") | bold | color(Color::Green),
            chat_input->Render(),
        }),
    });

    // Status bar visual
    auto status_el = text(" " + status_text) | dim | color(Color::White);

    auto layout = vbox({
        hbox({
            sidebar_el | size(WIDTH, EQUAL, 34) | border,
            chat_el | flex | border,
        }) | flex,
        status_el,
    });

    return layout;
  });

  screen.Loop(renderer);
}
