#pragma once

#include <atomic>
#include <condition_variable>
#include <string>
#include <map>
#include <functional>
#include <queue>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

class UserClient;

// ---- Data models ----

struct ServerEntry {
    std::string ip;
    std::string port;
    std::vector<std::string> groups;
    bool is_authenticated = false;
};

struct ChatMessage {
    std::string sender;
    std::string text;
};

struct RegisteredUserSelection {
    std::string name;
    bool selected = false;
};

// ---- TUI Driver ----

class TUIDriver {
public:
    TUIDriver(std::shared_ptr<UserClient> user_client);
    ~TUIDriver();

    // Register a command action (e.g. "send", "login")
    void add_action(std::string trigger, std::string guide,
                    std::function<void(std::string)> action);

    // Thread-safe: print a status line at the bottom bar
    void print_status(std::string output);

    // Add a server entry to the sidebar (call before or during run())
    void add_server(std::string ip, std::string port,
                    std::vector<std::string> groups);

    // Start the fullscreen FTXUI event loop (blocks until quit)
    void run();

private:
    std::shared_ptr<UserClient> user_client;
    std::atomic_bool is_running{true};

    // Guards all shared UI state below against the background polling threads.
    // The FTXUI thread (render + event + Post callbacks) and the poller threads
    // are the two sides that contend. Helpers (refresh_groups, add_server) run
    // with this already held by their caller.
    std::mutex state_mtx;

    // Action registry (same concept as REPLDriver)
    std::map<std::string, std::function<void(std::string)>> actions;
    std::map<std::string, std::string> guides;

    // ---- Sidebar state ----
    std::vector<ServerEntry> servers;
    std::vector<std::string> server_names;  // display strings for Menu
    int selected_server = -1;

    std::vector<std::string> current_groups; // groups of selected server
    int selected_group = -1;

    // Add-server form
    bool show_add_form = false;
    std::string new_ip;
    std::string new_port;
    int auth_mode = 0; // 0 = Login, 1 = Register

    // Add-group form
    bool show_create_group_form = false;
    std::string new_group_id;
    std::vector<RegisteredUserSelection> registered_users_selection;

    // ---- Chat state ----
    std::vector<ChatMessage> messages;
    std::string chat_input_text;
    std::map<std::string, std::vector<ChatMessage>> chat_history; // key: ip:port/group_id

    // ---- Status bar ----
    std::string status_text = "Ready. Add or select a server to begin.";

    // ---- Screen ----
    ftxui::ScreenInteractive screen = ftxui::ScreenInteractive::Fullscreen();

    // Background threads & helpers
    std::mutex shutdown_mtx;
    std::condition_variable shutdown_cv;
    std::thread periodic_group_checker_thread;
    std::thread active_group_fetcher_thread;

    // Background work (sends, connects, group creation) runs on a single
    // long-lived worker thread draining a queue, so rapid actions enqueue tasks
    // instead of spawning an unbounded number of threads. The tasks serialize on
    // UserClient's network mutex anyway, so one worker loses no concurrency.
    std::mutex worker_mtx;
    std::condition_variable worker_cv;
    std::queue<std::function<void()>> work_queue;
    std::thread worker_thread;

    void refresh_groups();
    void start_periodic_group_checker();
    void start_active_group_message_fetcher();
    void worker_loop();
    void launch_worker(std::function<void()> work);
};
