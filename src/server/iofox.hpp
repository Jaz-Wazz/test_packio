#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/basic_stream.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/file.hpp>
#include <boost/beast/core/file_base.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/chunk_encode.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/file_body.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/serializer.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/vector_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/http/buffer_body.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/core/noncopyable.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/url/urls.hpp>
#include <concepts>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <ios>
#include <sstream>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <fmt/core.h>
#include <openssl/tls1.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <utility>
#include <winnt.h>

#define asio		boost::asio
#define beast		boost::beast
#define this_coro	asio::this_coro
#define pbl			public:
#define prv			private:

namespace io
{
	// Type of async task, current asio::awaitable<T>.
	template <typename T> using coro = asio::awaitable<T>;

	// Token indicating to use async task, current asio::awaitable<T>.
	constexpr asio::use_awaitable_t<> use_coro;

	// Token indicating to use async task and return result as tuple.
	constexpr asio::as_tuple_t<asio::use_awaitable_t<>> use_coro_tuple;

	// Token indicating to exception should be rethrown.
	constexpr class
	{
		pbl void operator ()(std::exception_ptr ptr) const
		{
			if(ptr) std::rethrow_exception(ptr);
		}
	} rethrowed;

	// Service object - make T unique for any executors. [async_local c# alternative].
	template <typename T> class service: boost::noncopyable
	{
		pbl explicit service() {}

		prv class serv: public asio::execution_context::service, public std::optional<T>
		{
			pbl using key_type = serv;
			pbl using id = serv;
			pbl serv(asio::execution_context & ctx): asio::execution_context::service(ctx) {}
			pbl void shutdown() {}
		};

		pbl auto get_or_make(auto... args) -> io::coro<std::reference_wrapper<T>>
		{
			auto && context = (co_await this_coro::executor).context();
			if(!asio::has_service<serv>(context)) asio::make_service<serv>(context);
			serv & s = asio::use_service<serv>(context);
			if(!s) s.emplace(std::forward<decltype(args)>(args)...);
			co_return s.value();
		}
	};
}

namespace io::dns
{
	// Resolve dns record from context-global service.
	inline auto resolve(std::string protocol, std::string host) -> io::coro<asio::ip::tcp::resolver::results_type>
	{
		io::service<asio::ip::tcp::resolver> service;
		auto & resolver = (co_await service.get_or_make(co_await this_coro::executor)).get();
		co_return co_await resolver.async_resolve(host, protocol, io::use_coro);
	}
}

namespace io::ssl
{
	// Take ssl context instanse from context-global service.
	inline auto context() -> io::coro<std::reference_wrapper<asio::ssl::context>>
	{
		io::service<asio::ssl::context> service;
		co_return co_await service.get_or_make(asio::ssl::context::tls);
	}

	// Set hostname tls extension in stream.
	constexpr void set_tls_extension_hostname(auto & stream, std::string host)
	{
		auto status = SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());
		if(status == SSL_TLSEXT_ERR_ALERT_FATAL)
		{
			// [FIXME] - Use normal error handling in future.
			throw std::runtime_error(fmt::format("setting tls extension error, code: {}", status));
		}
	}

	inline auto handshake_http_client
	(
		beast::ssl_stream<beast::tcp_stream> & stream,
		const std::string & host,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	) -> io::coro<void>
	{
		// Set host name extension.
		io::ssl::set_tls_extension_hostname(stream, host);

		// Verify certificate hostname.
		stream.set_verify_callback(asio::ssl::host_name_verification(host));

		// Handshake.
		stream.next_layer().expires_after(timeout);
		co_await stream.async_handshake(asio::ssl::stream_base::client, io::use_coro);
		stream.next_layer().expires_never();
	}

	inline void load_ca_certificates(auto & executor, std::string path)
	{
		asio::co_spawn(executor, [=]() -> io::coro<void>
		{
			asio::ssl::context & ctx = co_await io::ssl::context();
			ctx.load_verify_file(path);
			ctx.set_verify_mode(asio::ssl::verify_peer);
		}, io::rethrowed);
	}
}

namespace io::windows
{
	// Windows language codes.
	enum class lang: LANGID { english = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) };

	// Change boost language in Windows for this thread.
	inline void set_asio_locale(lang code)
	{
		SetThreadUILanguage(static_cast<LANGID>(code));
	}
}

namespace io::meta
{
	// Concept check type is same std::vector<T> and sizeof(T) == 1 byte.
	template <typename T>		struct is_vector					: std::false_type {};
	template <typename... T>	struct is_vector<std::vector<T...>>	: std::true_type {};
	template <typename T>		concept vector_one_byte = is_vector<T>::value && sizeof(typename T::value_type) == 1;

	// Deduse body-type from underlying object-type. [std::string -> beast::http::string_body]
	template <typename>				struct make_body_type_impl				{ using type = void;												};
	template <>						struct make_body_type_impl<void>		{ using type = beast::http::empty_body;								};
	template <>						struct make_body_type_impl<std::string>	{ using type = beast::http::string_body;							};
	template <vector_one_byte T>	struct make_body_type_impl<T>			{ using type = beast::http::vector_body<typename T::value_type>;	};
	template <typename T> using make_body_type = typename make_body_type_impl<std::remove_reference_t<T>>::type;
}

namespace io
{
	inline auto open_https_stream(const asio::any_io_executor & executor, asio::ssl::context & context, const std::string & host)
	-> io::coro<beast::ssl_stream<beast::tcp_stream>>
	{
		// Namespaces.
		using namespace std::chrono_literals;

		// Create stream.
		beast::ssl_stream<beast::tcp_stream> stream {executor, context};

		// Connect.
		stream.next_layer().expires_after(19s);
		co_await stream.next_layer().async_connect(co_await io::dns::resolve("https", host), io::use_coro);
		stream.next_layer().expires_never();

		// Handshake.
		co_await io::ssl::handshake_http_client(stream, host);

		// Return stream.
		co_return stream;
	}

	inline auto open_https_stream(const std::string & host) -> io::coro<beast::ssl_stream<beast::tcp_stream>>
	{
		co_return co_await io::open_https_stream(co_await this_coro::executor, co_await io::ssl::context(), host);
	}
}

namespace io::http
{
	// Basic request object.
	template <typename T = void> class request: public beast::http::request<meta::make_body_type<T>>
	{
		prv using header_list = std::initializer_list<std::pair<std::string, std::string>>;

		pbl using beast::http::request<meta::make_body_type<T>>::operator=;
		pbl using beast::http::request<meta::make_body_type<T>>::operator[];

		pbl request(std::string method = "GET", std::string target = "/", header_list headers = {})
		{
			this->method_string(method);
			this->target(target);
			for(auto && [header, value] : headers) this->insert(header, value);
		}

		pbl template <typename X = T, typename std::enable_if<std::is_same_v<X, std::string>, int>::type = 0>
		request(std::string method, std::string target, header_list headers, const std::string & body)
		: request(std::move(method), std::move(target), std::move(headers))
		{ this->body() = body; }

		pbl template <typename X = T, typename std::enable_if<std::is_same_v<X, std::string>, int>::type = 0>
		request(std::string method, std::string target, header_list headers, const std::string && body)
		: request(std::move(method), std::move(target), std::move(headers))
		{ this->body() = std::move(body); }

		pbl template <typename X = T, typename std::enable_if<meta::vector_one_byte<X>, int>::type = 0>
		request(std::string method, std::string target, header_list headers, const std::vector<typename X::value_type> & body)
		: request(std::move(method), std::move(target), std::move(headers))
		{ this->body() = body; }

		pbl template <typename X = T, typename std::enable_if<meta::vector_one_byte<X>, int>::type = 0>
		request(std::string method, std::string target, header_list headers, const std::vector<typename X::value_type> && body)
		: request(std::move(method), std::move(target), std::move(headers))
		{ this->body() = std::move(body); }

		pbl void debug_dump()
		{
			fmt::print("[request] - {}\n", (std::stringstream() << *this).str());
		}
	};

	// Basic response object.
	template <typename T = void> class response: public beast::http::response<meta::make_body_type<T>>
	{
		prv using header_list = std::initializer_list<std::pair<std::string, std::string>>;
		pbl using beast::http::response<meta::make_body_type<T>>::operator=;
		pbl using beast::http::response<meta::make_body_type<T>>::operator[];

		pbl response(unsigned int result = 200, header_list headers = {})
		{
			this->result(result);
			for(auto && [header, value] : headers) this->insert(header, value);
		}

		pbl template <typename X = T, typename std::enable_if<std::is_same_v<X, std::string>, int>::type = 0>
		response(unsigned int result, header_list headers, const std::string & body): response(result, std::move(headers))
		{ this->body() = body; }

		pbl template <typename X = T, typename std::enable_if<std::is_same_v<X, std::string>, int>::type = 0>
		response(unsigned int result, header_list headers, std::string && body): response(result, std::move(headers))
		{ this->body() = std::move(body); }

		pbl template <typename X = T, typename std::enable_if<meta::vector_one_byte<X>, int>::type = 0>
		response(unsigned int result, header_list headers, const std::vector<typename X::value_type> & body): response(result, std::move(headers))
		{ this->body() = body; }

		pbl template <typename X = T, typename std::enable_if<meta::vector_one_byte<X>, int>::type = 0>
		response(unsigned int result, header_list headers, std::vector<typename X::value_type> && body): response(result, std::move(headers))
		{ this->body() = std::move(body); }

		pbl void check_code(int expected_code)
		{
			using base = beast::http::response<meta::make_body_type<T>>;
			if(base::result_int() != expected_code) throw std::runtime_error("unexpected_code");
		}

		pbl void check_header(const std::string_view header)
		{
			using base = beast::http::response<meta::make_body_type<T>>;
			if(base::operator[](header).empty()) throw std::runtime_error("unexpected_header");
		}

		pbl void check_contains_body()
		{
			using base = beast::http::response<meta::make_body_type<T>>;

			if(base::chunked() && !base::body().empty())
			{
				return;
			}

			if(base::has_content_length() && base::operator[]("Content-Length") != "0" && !base::body().empty())
			{
				return;
			}

			throw std::runtime_error("unexpected_empty_body");
		}

		pbl void check_not_contains_body()
		{
			using base = beast::http::response<meta::make_body_type<T>>;
			if(base::operator[]("Content-Length") != "0" || !base::body().empty())
			{
				throw std::runtime_error("unexpected_body");
			}
		}

		pbl void check_content_type(const std::string_view expected_type)
		{
			using base = beast::http::response<meta::make_body_type<T>>;
			if(base::at("Content-Type") != expected_type) throw std::runtime_error("unexpected_content_type");
		}

		pbl void debug_dump()
		{
			fmt::print("[response] - {}\n", (std::stringstream() << *this).str());
		}
	};

	// Basic request header object.
	class request_header: public beast::http::request_header<>
	{
		prv using base = beast::http::request_header<>;
		prv using header_list = std::initializer_list<std::pair<std::string, std::string>>;

		pbl using base::operator=;
		pbl using base::operator[];

		pbl request_header(std::string method = "GET", std::string target = "/", header_list headers = {})
		{
			this->method_string(method);
			this->target(target);
			for(auto && [header, value] : headers) this->insert(header, value);
		}

		pbl request_header(beast::http::request_header<> && header): base(std::move(header)) {}
	};

	// Basic response header object.
	class response_header: public beast::http::response_header<>
	{
		prv using base = beast::http::response_header<>;
		prv using header_list = std::initializer_list<std::pair<std::string, std::string>>;

		pbl using base::operator=;
		pbl using base::operator[];

		pbl response_header(unsigned int result = 200, header_list headers = {})
		{
			this->result(result);
			for(auto && [header, value] : headers) this->insert(header, value);
		}

		pbl response_header(beast::http::response_header<> && header): base(std::move(header)) {}
	};

	class connection_dumped: public std::exception
	{
		pbl const std::string request;
		pbl const std::string response;

		pbl connection_dumped(const auto & request, const auto & response)
		: request((std::stringstream() << request).str()), response((std::stringstream() << response).str()) {}

		pbl auto what() const noexcept -> const char * override
		{
			return "connection_dumped";
		}

		pbl void save_dump(std::filesystem::path path) const
		{
			std::ofstream(path, std::ios::binary) << request << '\n' << response << '\n';
		}
	};
}

namespace io::http::proxy
{
	class bad_ssl_tunnel: public std::exception
	{
		prv int value;

		pbl bad_ssl_tunnel(int code)
		: value(code) {}

		auto what() const noexcept -> const char *
		{
			return "bad_ssl_tunnel";
		}

		auto code() const -> const int
		{
			return value;
		}
	};

	inline auto open_ssl_tunnel
	(
		beast::tcp_stream & stream,
		std::string host,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	) -> io::coro<beast::ssl_stream<beast::tcp_stream>>
	{
		stream.expires_after(timeout);

		// Send connect request.
		io::http::request request {"CONNECT", host + ":443"};
		co_await beast::http::async_write(stream, request, io::use_coro);

		// Read connect response headers.
		beast::flat_buffer buffer;
		beast::http::response_parser<beast::http::empty_body> parser;
		co_await beast::http::async_read_header(stream, buffer, parser, io::use_coro);

		stream.expires_never();

		// Check status.
		if(parser.get().result_int() != 200) throw bad_ssl_tunnel(parser.get().result_int());

		// Construct overlying stream.
		co_return beast::ssl_stream<beast::tcp_stream>(std::move(stream), co_await io::ssl::context());
	}
}

namespace io::http
{
	template <typename T = std::string>
	inline auto send
	(
		beast::ssl_stream<beast::tcp_stream> & stream,
		const auto & request,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	)
	-> io::coro<io::http::response<T>>
	{
		stream.next_layer().expires_after(timeout);
		co_await beast::http::async_write(stream, request, io::use_coro);
		io::http::response<T> response;
		beast::flat_buffer buffer;
		co_await beast::http::async_read(stream, buffer, response, io::use_coro);
		stream.next_layer().expires_never();

		co_return response;
	}

	template <typename T = std::string>
	inline auto send
	(
		const boost::url url,
		const auto & request,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	)
	-> io::coro<io::http::response<T>>
	{
		if(url.scheme() != "https") throw std::runtime_error("unsupported_protocol");
		auto stream = co_await io::open_https_stream(url.host());
		co_return co_await io::http::send<T>(stream, request, timeout);
	}

	template <typename T = std::string>
	inline auto send
	(
		const std::string_view url,
		const auto & request,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	)
	-> io::coro<io::http::response<T>>
	{
		co_return co_await io::http::send<T>(boost::url(url), request, timeout);
	}

	template <typename T = std::string>
	inline auto send
	(
		const boost::url proxy,
		const boost::url url,
		const auto & request,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	)
	-> io::coro<io::http::response<T>>
	{
		if(proxy.scheme() != "https") throw std::runtime_error("unsupported_proxy_protocol");
		if(url.scheme() != "https") throw std::runtime_error("unsupported_protocol");

		beast::tcp_stream stream {co_await this_coro::executor};
		stream.expires_after(std::chrono::seconds(14));
		co_await stream.async_connect({asio::ip::make_address(proxy.host()), proxy.port_number()}, io::use_coro);
		stream.expires_never();

		beast::ssl_stream<beast::tcp_stream> tunnel = co_await io::http::proxy::open_ssl_tunnel(stream, url.host());
		co_await io::ssl::handshake_http_client(tunnel, url.host());
		co_return co_await io::http::send<T>(tunnel, request, timeout);
	}

	template <typename T = std::string>
	inline auto send
	(
		const boost::url proxy,
		const std::string_view url,
		const auto & request,
		const std::chrono::steady_clock::duration timeout = std::chrono::seconds(60)
	)
	-> io::coro<io::http::response<T>>
	{
		co_return co_await io::http::send<T>(proxy, boost::url(url), request, timeout);
	};
}

namespace io::error
{
	inline auto is_common_timeout(const boost::system::error_code & error_code)
	{
		// Check "The socket was closed due to a timeout".
		if(error_code == beast::error::timeout) return true;

		// Check "A connection attempt failed because the connected party did not properly respond after a period of time,
		// or established connection failed because connected host has failed to respond".
		if(error_code == asio::error::timed_out) return true;

		// Check "The semaphore timeout period has expired".
		if(error_code.category() == asio::error::system_category && error_code.value() == 121) return true;

		// Other errors not timeout.
		return false;
	};

	inline auto is_common_disconnect(const boost::system::error_code & error_code)
	{
		// Check "An established connection was aborted by the software in your host machine".
		if(error_code == asio::error::connection_aborted) return true;

		// Check "An existing connection was forcibly closed by the remote host".
		if(error_code == asio::error::connection_reset) return true;

		// Check "No connection could be made because the target machine actively refused it".
		if(error_code == asio::error::connection_refused) return true;

		// Check "End of stream".
		if(error_code == beast::http::error::end_of_stream) return true;

		// Other errors not disconnect.
		return false;
	};
}

#undef asio
#undef beast
#undef this_coro
#undef pbl
#undef prv
