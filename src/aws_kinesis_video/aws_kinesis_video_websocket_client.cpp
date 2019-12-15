#include "aws_kinesis_video_websocket_client.h"

#include <boost/beast/websocket/stream.hpp>
#include <nlohmann/json.hpp>

#include <aws/core/Aws.h>
#include <aws/core/client/AWSError.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/core/utils/memory/stl/AWSVector.h>
#include <aws/kinesisvideo/model/GetSignalingChannelEndpointRequest.h>
#include <aws/kinesisvideo/model/GetSignalingChannelEndpointResult.h>
#include <aws/kinesisvideo/model/SingleMasterChannelEndpointConfiguration.h>
#include <aws/kinesisvideo/model/ChannelRole.h>
#include <aws/kinesisvideo/model/ChannelProtocol.h>
#include <aws/kinesisvideo/model/ResourceEndpointListItem.h>
#include <aws/kinesisvideo/KinesisVideoClient.h>
#include <aws/kinesisvideo/KinesisVideoErrors.h>

#include "url_parts.h"
#include "util.h"

using json = nlohmann::json;

bool AwsKinesisVideoWebsocketClient::parseURL(URLParts& parts) const {
  std::string url = "";

  Aws::SDKOptions options;
  Aws::InitAPI(options);
  {
    Aws::Client::ClientConfiguration clientConfig;
    clientConfig.region = Aws::Region::AP_NORTHEAST_1; // TODO: get from env or parameter
    Aws::KinesisVideo::KinesisVideoClient kvs_client(clientConfig);

    std::string s = conn_settings_.aws_kinesis_video_signaling_channel_arn;
    Aws::String channel_arn(s.c_str(), s.size());

    Aws::KinesisVideo::Model::SingleMasterChannelEndpointConfiguration config;
    Aws::Vector<Aws::KinesisVideo::Model::ChannelProtocol> protocols = { Aws::KinesisVideo::Model::ChannelProtocol::WSS };
    config.SetProtocols(protocols);
    config.SetRole(Aws::KinesisVideo::Model::ChannelRole::MASTER);

    Aws::KinesisVideo::Model::GetSignalingChannelEndpointRequest req;
    req.SetChannelARN(channel_arn);
    req.SetSingleMasterChannelEndpointConfiguration(config);

    Aws::KinesisVideo::Model::GetSignalingChannelEndpointOutcome resp = kvs_client.GetSignalingChannelEndpoint(req);
    if (resp.IsSuccess()) {
      Aws::String const& endpoint = resp.GetResult().GetResourceEndpointList().at(0).GetResourceEndpoint();
      url = std::string(endpoint.c_str(), endpoint.size());
      RTC_LOG(LS_INFO) << __FUNCTION__ << " signaling url = " << url;
    } else {
      RTC_LOG(LS_ERROR) << __FUNCTION__ << "what :" << resp.GetError();
    }
  }
  Aws::ShutdownAPI(options);

  if (!URLParts::parse(url, parts)) {
    throw std::exception();
  }

  std::string default_port;
  if (parts.scheme == "wss") {
    return true;
  } else if (parts.scheme == "ws") {
    return false;
  } else {
    throw std::exception();
  }
}

boost::asio::ssl::context AwsKinesisVideoWebsocketClient::createSSLContext() const {
  boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv12);
  ctx.set_default_verify_paths();
  ctx.set_options(boost::asio::ssl::context::default_workarounds |
                  boost::asio::ssl::context::no_sslv2 |
                  boost::asio::ssl::context::no_sslv3 |
                  boost::asio::ssl::context::single_dh_use);
  return ctx;
}

webrtc::PeerConnectionInterface::IceConnectionState
AwsKinesisVideoWebsocketClient::getRTCConnectionState() const {
  return rtc_state_;
}

std::shared_ptr<RTCConnection> AwsKinesisVideoWebsocketClient::getRTCConnection() const {
  if (rtc_state_ == webrtc::PeerConnectionInterface::IceConnectionState::
                        kIceConnectionConnected) {
    return connection_;
  } else {
    return nullptr;
  }
}

AwsKinesisVideoWebsocketClient::AwsKinesisVideoWebsocketClient(boost::asio::io_context& ioc,
                                           RTCManager* manager,
                                           ConnectionSettings conn_settings)
    : ioc_(ioc),
      resolver_(ioc),
      manager_(manager),
      retry_count_(0),
      conn_settings_(conn_settings),
      watchdog_(ioc,
                std::bind(&AwsKinesisVideoWebsocketClient::onWatchdogExpired, this)) {
  reset();
}

void AwsKinesisVideoWebsocketClient::reset() {
  connection_ = nullptr;
  connected_ = false;
  is_send_offer_ = false;
  has_is_exist_user_flag_ = false;
  ice_servers_.clear();

  if (parseURL(parts_)) {
    auto ssl_ctx = createSSLContext();
    boost::beast::websocket::stream<
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>
        wss(ioc_, ssl_ctx);
    ws_.reset(new Websocket(ioc_, std::move(ssl_ctx)));
    // SNI の設定を行う
    if (!SSL_set_tlsext_host_name(
            ws_->nativeSecureSocket().next_layer().native_handle(),
            parts_.host.c_str())) {
      boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                   boost::asio::error::get_ssl_category()};
      MOMO_BOOST_ERROR(ec, "SSL_set_tlsext_host_name");
    }
  } else {
    boost::beast::websocket::stream<boost::asio::ip::tcp::socket> ws(ioc_);
    ws_.reset(new Websocket(ioc_));
  }
}

void AwsKinesisVideoWebsocketClient::release() {
  connection_ = nullptr;
}

bool AwsKinesisVideoWebsocketClient::connect() {
  RTC_LOG(LS_INFO) << __FUNCTION__;

  if (connected_) {
    return false;
  }

  std::string port;
  if (parts_.port.empty()) {
    port = ws_->isSSL() ? "443" : "80";
  } else {
    port = parts_.port;
  }

  // DNS ルックアップ
  resolver_.async_resolve(
      parts_.host, port,
      boost::asio::bind_executor(
          ws_->strand(),
          std::bind(&AwsKinesisVideoWebsocketClient::onResolve, shared_from_this(),
                    std::placeholders::_1, std::placeholders::_2)));

  watchdog_.enable(30);

  return true;
}

void AwsKinesisVideoWebsocketClient::reconnectAfter() {
  int interval = 5 * (2 * retry_count_ + 1);
  RTC_LOG(LS_INFO) << __FUNCTION__ << " reconnect after " << interval << " sec";

  watchdog_.enable(interval);
  retry_count_++;
}

void AwsKinesisVideoWebsocketClient::onWatchdogExpired() {
  RTC_LOG(LS_WARNING) << __FUNCTION__;

  RTC_LOG(LS_INFO) << __FUNCTION__ << " reconnecting...:";
  reset();
  connect();
}

void AwsKinesisVideoWebsocketClient::onResolve(
    boost::system::error_code ec,
    boost::asio::ip::tcp::resolver::results_type results) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "resolve");
  }

  // DNS ルックアップで得られたエンドポイントに対して接続する
  if (ws_->isSSL()) {
    boost::asio::async_connect(
        ws_->nativeSecureSocket().next_layer().next_layer(), results.begin(),
        results.end(),
        boost::asio::bind_executor(
            ws_->strand(),
            std::bind(&AwsKinesisVideoWebsocketClient::onSSLConnect, shared_from_this(),
                      std::placeholders::_1)));
  } else {
    boost::asio::async_connect(
        ws_->nativeSocket().next_layer(), results.begin(), results.end(),
        boost::asio::bind_executor(
            ws_->strand(),
            std::bind(&AwsKinesisVideoWebsocketClient::onConnect, shared_from_this(),
                      std::placeholders::_1)));
  }
}

void AwsKinesisVideoWebsocketClient::onSSLConnect(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "SSLConnect");
  }

  // SSL のハンドシェイク
  ws_->nativeSecureSocket().next_layer().async_handshake(
      boost::asio::ssl::stream_base::client,
      boost::asio::bind_executor(
          ws_->strand(), std::bind(&AwsKinesisVideoWebsocketClient::onSSLHandshake,
                                   shared_from_this(), std::placeholders::_1)));
}

void AwsKinesisVideoWebsocketClient::onSSLHandshake(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "SSLHandshake");
  }

  // Websocket のハンドシェイク
  ws_->nativeSecureSocket().async_handshake(
      parts_.host, parts_.path_query_fragment,
      boost::asio::bind_executor(
          ws_->strand(), std::bind(&AwsKinesisVideoWebsocketClient::onHandshake,
                                   shared_from_this(), std::placeholders::_1)));
}

void AwsKinesisVideoWebsocketClient::onConnect(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "connect");
  }
  // Websocket のハンドシェイク
  ws_->nativeSocket().async_handshake(
      parts_.host, parts_.path_query_fragment,
      boost::asio::bind_executor(
          ws_->strand(), std::bind(&AwsKinesisVideoWebsocketClient::onHandshake,
                                   shared_from_this(), std::placeholders::_1)));
}

void AwsKinesisVideoWebsocketClient::onHandshake(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "Handshake");
  }

  connected_ = true;

  ws_->startToRead(std::bind(&AwsKinesisVideoWebsocketClient::onRead, this,
                             std::placeholders::_1, std::placeholders::_2,
                             std::placeholders::_3));

  doRegister();
}

void AwsKinesisVideoWebsocketClient::doRegister() {
  json json_message = {
      {"type", "register"},
      {"clientId", Util::generateRandomChars()},
      {"roomId", conn_settings_.ayame_room_id},
  };
  if (conn_settings_.ayame_client_id != "") {
    json_message["clientId"] = conn_settings_.ayame_client_id;
  }
  if (conn_settings_.ayame_signaling_key != "") {
    json_message["key"] = conn_settings_.ayame_signaling_key;
  }
  ws_->sendText(json_message.dump());
}

void AwsKinesisVideoWebsocketClient::doSendPong() {
  json json_message = {{"type", "pong"}};
  ws_->sendText(json_message.dump());
}

void AwsKinesisVideoWebsocketClient::setIceServersFromConfig(json json_message) {
  // 返却されてきた iceServers を セットする
  if (json_message.contains("iceServers")) {
    auto jservers = json_message["iceServers"];
    if (jservers.is_array()) {
      for (auto jserver : jservers) {
        webrtc::PeerConnectionInterface::IceServer ice_server;
        if (jserver.contains("username")) {
          ice_server.username = jserver["username"];
        }
        if (jserver.contains("credential")) {
          ice_server.password = jserver["credential"];
        }
        auto jurls = jserver["urls"];
        for (const std::string url : jurls) {
          ice_server.urls.push_back(url);
          RTC_LOG(LS_INFO) << __FUNCTION__
                           << ": iceserver.url=" << std::string(url);
        }
        ice_servers_.push_back(ice_server);
      }
    }
  }
  if (ice_servers_.empty()) {
    // accept 時に iceServers が返却されてこなかった場合 google の stun server を用いる
    webrtc::PeerConnectionInterface::IceServer ice_server;
    ice_server.uri = "stun:stun.l.google.com:19302";
    ice_servers_.push_back(ice_server);
  }
}

void AwsKinesisVideoWebsocketClient::createPeerConnection() {
  webrtc::PeerConnectionInterface::RTCConfiguration rtc_config;

  rtc_config.servers = ice_servers_;
  connection_ = manager_->createConnection(rtc_config, this);
}

void AwsKinesisVideoWebsocketClient::close() {
  if (ws_->isSSL()) {
    ws_->nativeSecureSocket().async_close(
        boost::beast::websocket::close_code::normal,
        boost::asio::bind_executor(
            ws_->strand(),
            std::bind(&AwsKinesisVideoWebsocketClient::onClose, shared_from_this(),
                      std::placeholders::_1)));
  } else {
    ws_->nativeSocket().async_close(
        boost::beast::websocket::close_code::normal,
        boost::asio::bind_executor(
            ws_->strand(),
            std::bind(&AwsKinesisVideoWebsocketClient::onClose, shared_from_this(),
                      std::placeholders::_1)));
  }
}

void AwsKinesisVideoWebsocketClient::onClose(boost::system::error_code ec) {
  if (ec)
    return MOMO_BOOST_ERROR(ec, "close");
}

void AwsKinesisVideoWebsocketClient::onRead(boost::system::error_code ec,
                                  std::size_t bytes_transferred,
                                  std::string text) {
  RTC_LOG(LS_INFO) << __FUNCTION__ << ": " << ec;

  boost::ignore_unused(bytes_transferred);

  // 書き込みのために読み込み処理がキャンセルされた時にこのエラーになるので、これはエラーとして扱わない
  if (ec == boost::asio::error::operation_aborted)
    return;

  if (ec)
    return MOMO_BOOST_ERROR(ec, "Read");

  RTC_LOG(LS_INFO) << __FUNCTION__ << ": text=" << text;

  auto json_message = json::parse(text);
  const std::string type = json_message["type"];
  if (type == "accept") {
    setIceServersFromConfig(json_message);
    createPeerConnection();
    // isExistUser フラグが存在するか確認する
    auto is_exist_user = false;
    if (json_message.contains("isExistUser")) {
      has_is_exist_user_flag_ = true;
      is_exist_user = json_message["isExistUser"];
    }
    // isExistUser フラグが存在してかつ true な場合 offer SDP を生成して送信する
    if (is_exist_user) {
      RTC_LOG(LS_INFO) << __FUNCTION__ << ": exist_user";
      is_send_offer_ = true;
      connection_->createOffer();
    } else if (!has_is_exist_user_flag_) {
      // フラグがない場合とりあえず送信
      connection_->createOffer();
    }
  } else if (type == "offer") {
    // isExistUser フラグがなかった場合二回 peer connection を生成する
    if (!has_is_exist_user_flag_) {
      createPeerConnection();
    }
    const std::string sdp = json_message["sdp"];
    connection_->setOffer(sdp);
  } else if (type == "answer") {
    const std::string sdp = json_message["sdp"];
    connection_->setAnswer(sdp);
  } else if (type == "candidate") {
    int sdp_mlineindex = 0;
    std::string sdp_mid, candidate;
    json ice = json_message["ice"];
    sdp_mid = ice["sdpMid"];
    sdp_mlineindex = ice["sdpMLineIndex"];
    candidate = ice["candidate"];
    connection_->addIceCandidate(sdp_mid, sdp_mlineindex, candidate);
  } else if (type == "ping") {
    if (rtc_state_ != webrtc::PeerConnectionInterface::IceConnectionState::
                          kIceConnectionConnected) {
      return;
    }
    watchdog_.reset();
    doSendPong();
  }
}

// WebRTC からのコールバック
// これらは別スレッドからやってくるので取り扱い注意
void AwsKinesisVideoWebsocketClient::onIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  RTC_LOG(LS_INFO) << __FUNCTION__ << " state:" << new_state;
  boost::asio::post(ws_->strand(),
                    std::bind(&AwsKinesisVideoWebsocketClient::doIceConnectionStateChange,
                              shared_from_this(), new_state));
}
void AwsKinesisVideoWebsocketClient::onIceCandidate(const std::string sdp_mid,
                                          const int sdp_mlineindex,
                                          const std::string sdp) {
  // ayame では candidate sdp の交換で `ice` プロパティを用いる。 `candidate` ではないので注意
  json json_message = {
      {"type", "candidate"},
  };
  // ice プロパティの中に object で candidate 情報をセットして送信する
  json_message["ice"] = {{"candidate", sdp},
                         {"sdpMLineIndex", sdp_mlineindex},
                         {"sdpMid", sdp_mid}};
  ws_->sendText(json_message.dump());
}

void AwsKinesisVideoWebsocketClient::onCreateDescription(webrtc::SdpType type,
                                               const std::string sdp) {
  RTC_LOG(LS_INFO) << __FUNCTION__
                   << " SdpType: " << webrtc::SdpTypeToString(type);
  json json_message = {{"type", webrtc::SdpTypeToString(type)}, {"sdp", sdp}};
  ws_->sendText(json_message.dump());
}

void AwsKinesisVideoWebsocketClient::onSetDescription(webrtc::SdpType type) {
  RTC_LOG(LS_INFO) << __FUNCTION__
                   << " SdpType: " << webrtc::SdpTypeToString(type);

  boost::asio::post(ws_->strand(),
                    std::bind(&AwsKinesisVideoWebsocketClient::doSetDescription,
                              shared_from_this(), type));
}

void AwsKinesisVideoWebsocketClient::doIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  RTC_LOG(LS_INFO) << __FUNCTION__ << ": newState="
                   << Util::iceConnectionStateToString(new_state);

  switch (new_state) {
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionConnected:
      retry_count_ = 0;
      watchdog_.enable(60);
      break;
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionFailed:
      reconnectAfter();
      break;
    default:
      break;
  }
  rtc_state_ = new_state;
}

void AwsKinesisVideoWebsocketClient::doSetDescription(webrtc::SdpType type) {
  if (type == webrtc::SdpType::kOffer) {
    if (!is_send_offer_ || !has_is_exist_user_flag_) {
      connection_->createAnswer();
    }
    is_send_offer_ = false;
  }
}
