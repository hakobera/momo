#ifndef AWS_WSS_AUTH_SIGNER_
#define AWS_WSS_AUTH_SIGNER_

#include <cstdlib>
#include <memory>

#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/crypto/Sha256.h>
#include <aws/core/utils/crypto/Sha256HMAC.h>
#include <aws/core/utils/DateTime.h>

class AwsWssAuthSigner {

 public:
  AwsWssAuthSigner(
    const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>& credentialsProvider,
    const Aws::String& region);
  
  virtual ~AwsWssAuthSigner();

  Aws::String GenerateSignedURL(const Aws::String& endpoint, const Aws::String& channel_arn) const;

 private:
  Aws::String GenerateCanonicalQueryString(const Aws::String& channel_arn, const Aws::String& access_key_id, const Aws::String& credential_scope, const Aws::String& datetime_string, const Aws::String& signed_headers) const;
  Aws::String GenerateCanonicalHeadersString(const Aws::String& host) const;
  Aws::Utils::ByteBuffer GetSignatureKey(const Aws::String& secret_key, const Aws::String& simple_date, const Aws::String& region, const Aws::String& service_name) const;

  Aws::Utils::DateTime GetSigningTimestamp() const;

  std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentialsProvider_;
  Aws::String region_;
  Aws::String service_name_;
  Aws::UniquePtr<Aws::Utils::Crypto::Sha256> hash_;
  Aws::UniquePtr<Aws::Utils::Crypto::Sha256HMAC> HMAC_;
};

#endif // AWS_WSS_AUTH_SIGNER_