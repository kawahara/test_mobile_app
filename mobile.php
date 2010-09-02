<?php

// サンプルアプリ (非実用)
// (curlが必要です)
//
// 使い方
// 1. XMLファイル, このファイル, および OAuthのライブラリをWebサーバへ
// 2. XMLファイルのURLをこのファイルのURLへ
// 3. SNSの管理画面からXMLファイルを登録 (および ConsumerKey, ConsumerSecretの入手)
// 4. SNSのCertificateを貼りつけ


define('CONSUMER_KEY', '');
define('CONSUMER_SECRET', '');
define('BASE_URL', '');

include_once './oauth/OAuth.php';

function do_get($uri, $data = '')
{
  $h = curl_init();
  curl_setopt($h, CURLOPT_URL, $uri.'?'.$data);
  curl_setopt($h, CURLOPT_POST, false);
  curl_setopt($h, CURLOPT_RETURNTRANSFER, true);

  $result = curl_exec($h);

  curl_close($h);

  return $result;
}

class OAuthSignatureMethod_RSA_SHA1_opOpenSocialPlugin extends OAuthSignatureMethod_RSA_SHA1
{
  protected function fetch_private_cert(&$request) {
  }

  protected function fetch_public_cert(&$request) {
    return <<<EOT
Certificateを貼りつけてください
EOT;
  }
}

$request = OAuthRequest::from_request(null, null, null);
$signature_method = new OAuthSignatureMethod_RSA_SHA1_opOpenSocialPlugin();
if (!$signature_method->check_signature($request, null, null, $request->get_parameter('oauth_signature')))
{
  header('HTTP', true, 403);
  exit;
}


$consumer = new OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET);
$request = OAuthRequest::from_consumer_and_token(
  $consumer,
  null,
  'GET',
  BASE_URL.'/api.php/social/rest/people/@me/@self'
);
$request->set_parameter('xoauth_requestor_id', $_GET['opensocial_owner_id']);
$request->sign_request(new OAuthSignatureMethod_HMAC_SHA1(), $consumer, null);
$res = do_get($request->get_normalized_http_url(), $request->to_postdata());
$json = json_decode($res, true);

?>
<?php echo "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ja" dir="ltr">
<head>
  <meta http-equiv="Content-Type" content="application/xhtml+xml; charset=UTF-8" />
  <title>サンプルなアプリです</title>
  <style type="text/css">
    <![CDATA[
      a:link{color:#ffffff;}
      a:visited{color:#ffffff;}
      a:focus{}
      *{
        font-size:x-small;
        color:#ffd83d;
      }
    ]]>
  </style>
</head>
<body>
<?php
echo 'あなたのIDは'.$json['entry']['id'].'です';
?>
</body>
</html>
