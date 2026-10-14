#include <stdexcept>
#include <cstdint>
#include <vector>

#include "../../include/drivers/network_driver.hpp"

using namespace boost::asio;
using ip::tcp;

namespace {
constexpr size_t kMaxFrameBytes = 1024 * 1024;
}

/**
 * Constructor. Sets up IO context and socket.
 */
NetworkDriverImpl::NetworkDriverImpl() : io_context() {
  this->socket = std::make_shared<tcp::socket>(io_context);
}

/**
 * Listen on the given port at localhost.
 * @param port Port to listen on.
 */
void NetworkDriverImpl::listen(int port) {
  tcp::acceptor acceptor(this->io_context, tcp::endpoint(tcp::v4(), port));
  acceptor.accept(*this->socket);
}

/**
 * Connect to the given address and port.
 * @param address Address to connect to.
 * @param port Port to conect to.
 */
void NetworkDriverImpl::connect(std::string address, int port) {
  if (address == "localhost")
    address = "127.0.0.1";
  this->socket->connect(
      tcp::endpoint(boost::asio::ip::make_address(address), port));
}

/**
 * Disconnect graceefully.
 */

void NetworkDriverImpl::disconnect() {
  // Cleanup must be idempotent: if the peer already closed the socket, the
  // throwing overloads raise "Socket is not connected", and because callers
  // disconnect() in both the try and the catch, that second throw would escape
  // the connection thread and terminate the whole process. Use the non-throwing
  // error_code overloads (guarded by is_open) so teardown is always a safe no-op.
  boost::system::error_code ec;
  if (this->socket && this->socket->is_open()) {
    this->socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    this->socket->close(ec);
  }
  this->io_context.stop();
}

/**
 * Sends a fixed amount of data by sending length first.
 * @param data Bytes of data to send.
 */
void NetworkDriverImpl::send(std::vector<unsigned char> data) {
  if (data.size() > kMaxFrameBytes)
    throw std::runtime_error("Refusing to send an oversized network frame.");
  uint32_t length = htonl(static_cast<uint32_t>(data.size()));
  boost::asio::write(*this->socket, boost::asio::buffer(&length, sizeof(length)));
  boost::asio::write(*this->socket, boost::asio::buffer(data));
}

/**
 * Receives a fixed amount of data by receiving length first.
 * @return std::vector<unsigned char> data read.
 * @throws error when eof.
 */
std::vector<unsigned char> NetworkDriverImpl::read() {
  // read length
  uint32_t wire_length = 0;
  boost::system::error_code error;
  boost::asio::read(*this->socket, boost::asio::buffer(&wire_length, sizeof(wire_length)),
                    boost::asio::transfer_exactly(sizeof(wire_length)), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  const size_t length = ntohl(wire_length);
  if (length > kMaxFrameBytes)
    throw std::runtime_error("Received oversized network frame.");

  // read message
  std::vector<unsigned char> data;
  data.resize(length);
  boost::asio::read(*this->socket, boost::asio::buffer(data),
                    boost::asio::transfer_exactly(length), error);
  if (error) {
    throw std::runtime_error("Received EOF.");
  }
  return data;
}

/**
 * Get socket info as string.
 */
std::string NetworkDriverImpl::get_remote_info() {
  return this->socket->remote_endpoint().address().to_string() + ":" +
         std::to_string(this->socket->remote_endpoint().port());
}
