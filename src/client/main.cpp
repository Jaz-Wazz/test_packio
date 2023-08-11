
#include <iofox.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <packio/msgpack_rpc/rpc.h>
#include <packio/client.h>
#include <fmt/core.h>
#include <exception>
#include <vector>
#include <array>
#include <tuple>

namespace asio { using namespace boost::asio; }

auto coro(asio::io_context & executor) -> io::coro<void>
{
	asio::ip::tcp::socket socket {executor};
	co_await socket.async_connect({asio::ip::make_address("127.0.0.1"), 555}, io::use_coro);

	std::vector<char> buffer = {'g', 'a', 'r', 'o', 'x'};

	// char * buffer = new char[128];
	// auto buffer = new std::array<char, 128>;

	auto client = packio::make_client<packio::msgpack_rpc::rpc>(std::move(socket));
	co_await client->async_call("some_foo", std::tuple(buffer), io::use_coro);

	fmt::print("sis.\n");
	co_return;
}

int main() try
{
	io::windows::set_asio_locale(io::windows::lang::english);
	asio::io_context ctx;
	asio::co_spawn(ctx, coro(ctx), io::rethrowed);
	ctx.run();
	return 0;
}
catch(const std::exception & exception)
{
	fmt::print("[main] - exception: '{}'.\n", exception.what());
}
