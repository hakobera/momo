#ifndef AWS_KINSIS_VIDEO_WEBSOCKET_CLIENT_
#define AWS_KINSIS_VIDEO_WEBSOCKET_CLIENT_

#include <algorithm>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstdlib>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

#include "connection_settings.h"
#include "rtc/manager.h"
#include "rtc/messagesender.h"
#include "url_parts.h"
#include "watchdog.h"
#include "ws/websocket.h"

class AwsKinesisVideoWebsocketClient
    : public std::enable_shared_from_this<AwsKinesisVideoWebsocketClient>,
      public RTCMessageSender {
  boost::asio::io_context& ioc_;

  boost::asio::ip::tcp::resolver resolver_;

  std::unique_ptr<Websocket> ws_;

  URLParts parts_;

  RTCManager* manager_;
  std::shared_ptr<RTCConnection> connection_;
  ConnectionSettings conn_settings_;

  int retry_count_;
  webrtc::PeerConnectionInterface::IceConnectionState rtc_state_;

  WatchDog watchdog_;

  bool connected_;
  std::string client_id_;

  webrtc::PeerConnectionInterface::IceServers ice_servers_;
  
 private:
  bool parseURL(URLParts& parts);
  boost::asio::ssl::context createSSLContext() const;

 public:
  webrtc::PeerConnectionInterface::IceConnectionState getRTCConnectionState()
      const;
  std::shared_ptr<RTCConnection> getRTCConnection() const;

 public:
  AwsKinesisVideoWebsocketClient(boost::asio::io_context& ioc,
                       RTCManager* manager,
                       ConnectionSettings conn_settings);
  void reset();

 public:
  // connection_ = nullptr すると直ちに onIceConnectionStateChange コールバックが呼ばれるが、
  // この中で使っている shared_from_this() がデストラクタ内で使えないため、デストラクタで connection_ = nullptr すると実行時エラーになる。
  // なのでこのクラスを解放する前に明示的に release() 関数を呼んでもらうことにする。
  void release();

 public:
  bool connect();

 private:
  void reconnectAfter();
  void onWatchdogExpired();

 private:
  void onResolve(boost::system::error_code ec,
                 boost::asio::ip::tcp::resolver::results_type results);
  void onSSLConnect(boost::system::error_code ec);
  void onSSLHandshake(boost::system::error_code ec);
  void onConnect(boost::system::error_code ec);
  void onHandshake(boost::system::error_code ec);
  void setIceServersFromConfig(nlohmann::json json_message);
  void createPeerConnection();

 public:
  void close();

 private:
  void onClose(boost::system::error_code ec);

 private:
  void onRead(boost::system::error_code ec,
              std::size_t bytes_transferred,
              std::string text);

 private:
  std::string generateRandomClientId();

 private:
  // WebRTC からのコールバック
  // これらは別スレッドからやってくるので取り扱い注意
  void onIceConnectionStateChange(
      webrtc::PeerConnectionInterface::IceConnectionState new_state) override;
  void onIceCandidate(const std::string sdp_mid,
                      const int sdp_mlineindex,
                      const std::string sdp) override;
  void onCreateDescription(webrtc::SdpType type,
                           const std::string sdp) override;
  void onSetDescription(webrtc::SdpType type) override;

 private:
  void doIceConnectionStateChange(
      webrtc::PeerConnectionInterface::IceConnectionState new_state);
  void doSetDescription(webrtc::SdpType type);
};

#endif  // AWS_KINSIS_VIDEO_WEBSOCKET_CLIENT_