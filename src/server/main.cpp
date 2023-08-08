
#include <iofox.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <packio/json_rpc/rpc.h>
#include <packio/dispatcher.h>
#include <packio/server.h>
#include <fmt/core.h>
#include <exception>

namespace asio { using namespace boost::asio; }

int main() try
{
	io::windows::set_asio_locale(io::windows::lang::english);
	asio::io_context ctx;

	asio::ip::tcp::acceptor acceptor {ctx, {asio::ip::make_address("127.0.0.1"), 555}};
	auto server = packio::make_server<packio::json_rpc::rpc>(std::move(acceptor));

	server->dispatcher()->add_coro("some_foo", ctx, [] -> io::coro<void>
	{
		fmt::print("message");
		co_return;
	});

	server->async_serve_forever();

	ctx.run();
	return 0;
}
catch(const std::exception & exception)
{
	fmt::print("[main] - exception: '{}'.\n", exception.what());
}
