#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include/pkg/escrow.hpp"

int main(int argc, char *argv[]) {
  // Config
  if (argc != 2) {
    std::cout << "Usage: ./escrow <escrow_config_path>" << std::endl;
    return 1;
  }
  std::string escrow_config_path = argv[1];

  try {
    EscrowConfig escrow_config = load_escrow_config(escrow_config_path);
    EscrowClient escrow_client = EscrowClient(escrow_config);
    escrow_client.run();
  } catch (std::exception &e) {
    std::cerr << "Error running escrow process: " << e.what() << std::endl;
    return 1;
  } catch (const char *e) {
    std::cerr << "Error running escrow process: " << e << std::endl;
    return 1;
  }

  return 0;
}
