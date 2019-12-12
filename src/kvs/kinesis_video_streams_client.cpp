#include "kinesis_video_streams_client.h"

#include <nlohmann/json.hpp>

#include "util.h"

using json = nlohmann::json;

void KinesisVideoStreamsClient::init() const {
  STATUS retStatus = STATUS_SUCCESS;
  return;
}

webrtc::PeerConnectionInterface::IceConnectionState
KinesisVideoStreamsClient::getRTCConnectionState() const {
  return rtc_state_;
}

std::shared_ptr<RTCConnection> KinesisVideoStreamsClient::getRTCConnection() const {
  if (rtc_state_ == webrtc::PeerConnectionInterface::IceConnectionState::
                        kIceConnectionConnected) {
    return connection_;
  } else {
    return nullptr;
  }
}

KinesisVideoStreamsClient::KinesisVideoStreamsClient(boost::asio::io_context& ioc,
                                           RTCManager* manager,
                                           ConnectionSettings conn_settings)
    : ioc_(ioc),
      resolver_(ioc),
      manager_(manager),
      retry_count_(0),
      conn_settings_(conn_settings),
      watchdog_(ioc,
                std::bind(&KinesisVideoStreamsClient::onWatchdogExpired, this)) {
  reset();
}

void KinesisVideoStreamsClient::reset() {
  connection_ = nullptr;
  connected_ = false;
  is_send_offer_ = false;
  has_is_exist_user_flag_ = false;
  ice_servers_.clear();
}

void KinesisVideoStreamsClient::release() {
  connection_ = nullptr;
}

bool KinesisVideoStreamsClient::connect() {
  RTC_LOG(LS_INFO) << __FUNCTION__;

  if (connected_) {
    return false;
  }

  watchdog_.enable(30);
  return true;
}

void KinesisVideoStreamsClient::reconnectAfter() {
  int interval = 5 * (2 * retry_count_ + 1);
  RTC_LOG(LS_INFO) << __FUNCTION__ << " reconnect after " << interval << " sec";

  watchdog_.enable(interval);
  retry_count_++;
}

void KinesisVideoStreamsClient::onWatchdogExpired() {
  RTC_LOG(LS_WARNING) << __FUNCTION__;

  RTC_LOG(LS_INFO) << __FUNCTION__ << " reconnecting...:";
  reset();
  connect();
}

void KinesisVideoStreamsClient::onResolve(
    boost::system::error_code ec,
    boost::asio::ip::tcp::resolver::results_type results) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "resolve");
  }
}

void KinesisVideoStreamsClient::onSSLConnect(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "SSLConnect");
  }
}

void KinesisVideoStreamsClient::onSSLHandshake(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "SSLHandshake");
  }
}

void KinesisVideoStreamsClient::onConnect(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "connect");
  }
}

void KinesisVideoStreamsClient::onHandshake(boost::system::error_code ec) {
  if (ec) {
    reconnectAfter();
    return MOMO_BOOST_ERROR(ec, "Handshake");
  }

  connected_ = true;

  doRegister();
}

void KinesisVideoStreamsClient::doRegister() {
}

void KinesisVideoStreamsClient::doSendPong() {
}

void KinesisVideoStreamsClient::setIceServersFromConfig(json json_message) {
}

void KinesisVideoStreamsClient::createPeerConnection() {
  webrtc::PeerConnectionInterface::RTCConfiguration rtc_config;

  rtc_config.servers = ice_servers_;
  connection_ = manager_->createConnection(rtc_config, this);
}

void KinesisVideoStreamsClient::close() {
}

void KinesisVideoStreamsClient::onClose(boost::system::error_code ec) {
  if (ec)
    return MOMO_BOOST_ERROR(ec, "close");
}

void KinesisVideoStreamsClient::onRead(boost::system::error_code ec,
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
}

// WebRTC からのコールバック
// これらは別スレッドからやってくるので取り扱い注意
void KinesisVideoStreamsClient::onIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  RTC_LOG(LS_INFO) << __FUNCTION__ << " state:" << new_state;
}

void KinesisVideoStreamsClient::onIceCandidate(const std::string sdp_mid,
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
}

void KinesisVideoStreamsClient::onCreateDescription(webrtc::SdpType type,
                                               const std::string sdp) {
  RTC_LOG(LS_INFO) << __FUNCTION__
                   << " SdpType: " << webrtc::SdpTypeToString(type);
}

void KinesisVideoStreamsClient::onSetDescription(webrtc::SdpType type) {
  RTC_LOG(LS_INFO) << __FUNCTION__
                   << " SdpType: " << webrtc::SdpTypeToString(type);
}

void KinesisVideoStreamsClient::doIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  RTC_LOG(LS_INFO) << __FUNCTION__ << ": newState="
                   << Util::iceConnectionStateToString(new_state);
  rtc_state_ = new_state;
}

void KinesisVideoStreamsClient::doSetDescription(webrtc::SdpType type) {
  if (type == webrtc::SdpType::kOffer) {
    if (!is_send_offer_ || !has_is_exist_user_flag_) {
      connection_->createAnswer();
    }
    is_send_offer_ = false;
  }
}
