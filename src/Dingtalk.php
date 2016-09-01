<?php

include_once dirname(__FILE__)."/dingtalk/crypto/sha1.php";
include_once dirname(__FILE__)."/dingtalk/crypto/pkcs7Encoder.php";
include_once dirname(__FILE__)."/dingtalk/crypto/errorCode.php";
require_once dirname(__FILE__)."/Curl.php";
require_once dirname(__FILE__)."/Filecache.php";

/**
* 叮叮服务端sdk
* @author bitcao <znddzxx112@163.com>
*/
/**
 * 建立连接
 * 管理通讯录
 * 管理微应用
 * 群会话接口
 * 通讯录及群会话变更事件回调接口
 * 发送普通会话消息
 * 发送企业会话消息
 * 管理多媒体文件
 * 免登
 * 普通钉钉用户账号开放
 * 加密解密
 * JS接口API
 */

class Dingtalk
{
	/**
	 * 企业
	 */
	private $corpid='';
	private $corpsecret = '';
	private $host='';
	private $agentid='';
	private $url='';//dingding后台url

	/**
	 * isv 套件
	 */
	private $token='';
	private $encodingAesKey='';
	private $suiteKey='';
	private $create_suite_key='';

	/**
	 * 加解密
	 */
	private $m_token;
	private $m_encodingAesKey;
	private $m_suiteKey;

	/**
	 * 开放应用
	 */
	private $appid='';
	private $appsecret='';

	/**
	 * cache类型
	 * file cache_service redis
	 * @var string
	 */
	private $cache_type='file';

	private $curl = null;

	private $filecache = null;

	function __construct($conf='')
	{
		if($conf!=''){
			if(is_array($conf)){
				foreach ($conf as $k => $v) {
					isset($this->$k) && $this->$k = $v;
				}
			}
		}
		if($this->curl == null){
			$this->curl = new Curl();
		}
		if($this->filecache == null){
			$this->filecache = new Filecache(array('root_dir'=>dirname(__file__).'/../cache/'));
		}
	}
	function __destruct()
	{
		if($this->curl != null){
			$this->curl = null;
		}
		if($this->filecache == null){
			$this->filecache = null;
		}
	}

	/**
	 * 返回corpid
	 * @return [type] [description]
	 */
	public function getCorpid()
	{
		return $this->corpid;
	}

	/**
	 * start of 管理通讯录
	 */
	/**
	 * 获取部门列表
	 * 
	 */
	public function departmentListDept(){
		$accessToken = $this->getAccessToken();
		$response=$this->httpGet('department/list',array('access_token'=>$accessToken));
		return $response;
	}
	/**
	 * 获取部门详情
	 * @param  integer $id 部门id
	 * @return [type]     [description]
	 */
	public function departmentGetInfo($id){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('department/get',array('access_token'=>$accessToken,'id'=>$id));
		return $response;
	}
	/**
	 * 创建部门
	 * @param  array $dept 部门详情
	 * @return [type]       [description]
	 */
	public function departmentCreateDept($dept=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('department/create?access_token='.$accessToken,$dept);
		return $response;
	}
	/**
	 * 更新部门
	 * @param  array $dept 部门详情
	 */
	public function departmentUpdateDept($dept=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('department/update?access_token='.$accessToken,$dept);
		return $response;
	}
	/**
	 * 删除部门
	 * @param  [type] $id [description]
	 * @return [type]     [description]
	 */
	public function departmentDeleteDept($id){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('department/delete',array('access_token'=>$accessToken,'id'=>$id));
		return $response;
	}
	/**
	 * 获取成员详情
	 * @param  [type] $userid [description]
	 * @return [type]         [description]
	 */
	public function userGetInfo($userid){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('user/get',array('access_token'=>$accessToken,'userid'=>$userid));
		return $response;
	}
	/**
	 * 获取部门成员
	 * @param  integer $department_id 获取的部门id
	 * @return [type]                [description]
	 */
	public function userGetSimpleList($department_id){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('user/simplelist',array('access_token'=>$accessToken,'department_id'=>$department_id));
		return $response;
	}
	/**
	 * 获取部门成员
	 * @param  integer $department_id 获取的部门id
	 * @return [type]                [description]
	 */
	public function userGetList($department_id){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('user/list',array('access_token'=>$accessToken,'department_id'=>$department_id));
		return $response;
	}
	/**
	 * end of 管理通讯录
	 */

	/**
	 * start of 管理微应用
	 */
	/**
	 * 获取企业设置的微应用可见范围
	 * @param  [type] $agentId 需要查询询的微应用agentId
	 * @return [type]          [description]
	 */
	public function microappGetVisibleScopes($agentId){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('microapp/visible_scopes?access_token='.$accessToken,array('agentId'=>$agentId));
		return $response;
	}	
	/**
	 * end of 管理微应用
	 */

	/**
	 * start of 群会话接口
	 */
	/**
	 * 创建会话
	 * @param  array  $group [description]
	 * @return [type]        [description]
	 */
	public function chatCreate($group=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('chat/create?access_token='.$accessToken,$group);
		return $response;
	}
	/**
	 * 获取会话
	 * @param  [type] $chatid 群会话的id
	 * @return [type]         [description]
	 */
	public function chatGet($chatid){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('chat/get',array('access_token'=>$accessToken,'chatid'=>$chatid));
		return $response;
	}
	/**
	 * 发送消息到群会话
	 * @param  array  $content [description]
	 * @return [type]          [description]
	 */
	public function chatSend($content=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('chat/send?access_token='.$accessToken,$content);
		return $response;
	}
	/**
	 * end of 群会话接口
	 */

	/**
	 * start of 通讯录及群会话变更事件回调接口
	 */
	
	/**
	 * 注册事件回调接口
	 * @param  string $call_back_tag 需要监听的事件类型
	 * @param  string $url           接收事件回调的url
	 * @return [type]                [description]
	 */
	public function callBackRegisterEvent($call_back_tag='',$url=''){
		$accessToken = $this->getAccessToken();
		$token = $this->token;
		$aes_key = $this->encodingAesKey;
		$response = $this->httpPost('call_back/register_call_back?access_token='.$accessToken,
						array('call_back_tag'=>$call_back_tag,'token'=>$token,
							'aes_key'=>$aes_key,'url'=>$url));
		return $response;
	}
	/**
	 * 查询事件回调接口
	 * @return [type] [description]
	 */
	public function callBackGetEventList(){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('call_back/get_call_back',array('access_token'=>$accessToken));
		return $response;
	}
	/**
	 * end of 通讯录及群会话变更事件回调接口
	 */

	/**
	 * start of 发送普通会话消息
	 */
	/**
	 * 发送普通会话消息接口说明
	 * 员工可以在微应用中把消息发送到同企业的人或群
	 * @param  array  $content [description]
	 * @return [type]          [description]
	 */
	public function messageSendToConversation($content=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('message/send_to_conversation?access_token='.$accessToken,$content);
		return $response;
	}
	/**
	 * end of 发送普通会话消息
	 */
	
	/**
	 * start of 发送企业会话消息
	 */
	/**
	 * 发送企业消息接口说明
	 * 企业可以主动发消息给员工，消息量不受限制
	 * @param  array  $content [description]
	 * @return [type]          [description]
	 */
	public function messageSend($content=array()){
		$accessToken = $this->getAccessToken();
		$response = $this->httpPost('message/send?access_token='.$accessToken,$content);
		return $response;
	}
	/**
	 * end of 发送企业会话消息
	 */

	/**
	 * start of 管理多媒体文件
	 */
	/**
	 * 上传媒体文件
	 * @param  string $type  [description]
	 * @param  array  $media [description]
	 * @return [type]        [description]
	 */
	public function mediaUpload($type='',$media=array()){
		$accessToken = $this->getAccessToken();
		@$response = $this->httpRawPost('media/upload?access_token='.$accessToken.'&type='.$type,$media);
		return $response;
	}
	/**
	 * 获取媒体文件
	 * @param  string $media_id  媒体文件的唯一标示
	 * @param  string $filename  保存文件名称
	 * @param  string $save_path 保存文件路径
	 * @return [type]            [description]
	 */
	public function mediaDownload($media_id='', $filename='', $save_path=''){
		$accessToken = $this->getAccessToken();
		$host = $this->host;
		$url = 'media/get?access_token='.$accessToken.'&media_id='.$media_id;
		$real_url = $host.'/'.$url;
        $this->curl->init();
        $this->curl->setOption(CURLOPT_FOLLOWLOCATION,true);//必须支持301 302 307
        $file_info = $this->curl->get($real_url);
        // echo __line__.':'.$real_url;
        $this->curl->close();
        $fileExt = $this->judge_file_type($file_info);
        $filename = $filename . "." . $fileExt;
        if (!file_exists($save_path)) {
            mkdir($save_path, 0777, true);
        }
        file_put_contents($save_path . $filename, $file_info);
	}
	/**
	 * end of 管理多媒体文件
	 */
	
	/**
	 * start of 免登
	 */
	/**
	 * 获取jsApi凭证配置
	 * @return [type] [description]
	 */
	public function getjsApiConfig($corpid='')
	{
		$nonceStr = 'dingzjbook';
        $timeStamp = time();
        $url   = $this->url;
        $corpid = $this->corpid;//企业corpid
        $agentid = $this->agentid;

        $ticket = $this->getJsApiticket();
        $signature = $this->sign($ticket, $nonceStr, $timeStamp, $url);
        $config = array(
        	'agentId'=>$agentid,
            'url' => $url,
            'nonceStr' => $nonceStr,
            'timeStamp' => $timeStamp,
            'corpId' => $corpid,
            'signature' => $signature);
        return json_encode($config, JSON_UNESCAPED_SLASHES);
	}
	/**
	 * 通过CODE换取用户身份
	 * @param  string $code 通过Oauth认证会给URL带上CODE
	 * @return [type]       [description]
	 */
	public function userGetUserInfo($code=''){
		$accessToken = $this->getAccessToken();
		$response = $this->httpGet('user/getuserinfo',array('access_token'=>$accessToken,'code'=>$code));
		return $response;
	}
	/**
	 * end of 免登
	 */

	/**
	 * start of 普通钉钉用户账号开放
	 */
	/**
	 * 获取钉钉开放应用的ACCESS_TOKEN
	 * @param  string $appid     由钉钉开放平台提供给开放应用的唯一标识
	 * @param  string $appsecret 由钉钉开放平台提供的密钥
	 * @return [type]            [description]
	 */
	public function snsGetToken(){
		/**
         * 缓存sns_accessToken。accessToken有效期为两小时，需要在失效前请求新的accessToken（注意：以下代码没有在失效前刷新缓存的accessToken）。
         */
        $accessToken = $this->getCache('sns_access_token');
        if ($accessToken == '' || $accessToken == false)
        {
            $appid = $this->appid;
            $appsecret = $this->appsecret;
            $response = $this->httpGet('sns/gettoken',array('appid'=>$appid,'appsecret'=>$appsecret));
            if($response['errcode'] == 0){//正确返回
            	$accessToken = $response['access_token'];
            	$this->setCache('sns_access_token',$accessToken);
            }
        }
        return $accessToken;
	}
	/**
	 * 获取用户授权的持久授权码
	 * @param  string $tmp_auth_code 用户授权给钉钉开放应用的临时授权码
	 * @return [type]                [description]
	 */
	public function snsGetPersistentCode($tmp_auth_code=''){
		$accessToken = $this->snsGetToken();
		$response = $this->httpPost('sns/get_persistent_code?access_token='.$accessToken,array('tmp_auth_code'=>$tmp_auth_code));
		return $response;
	}
	/**
	 * 获取用户授权的SNS_TOKEN
	 * @param  string $openid          用户的openid
	 * @param  string $persistent_code 用户授权给钉钉开放应用的持久授权码
	 * @return [type]                  [description]
	 */
	public function snsGetSnsToken($openid='',$persistent_code=''){
		$accessToken = $this->snsGetToken();
		$response = $this->httpPost('sns/get_sns_token?access_token='.$accessToken,array('openid'=>$openid,'persistent_code'=>$persistent_code));
		return $response;
	}
	/**
	 * 获取用户授权的个人信息
	 * @param  string $sns_token [description]
	 * @return [type]            [description]
	 */
	public function snsGetUserInfo($sns_token=''){
		$response = $this->httpGet('sns/getuserinfo',array('sns_token'=>$sns_token));
		return $response;
	}
	/**
	 * end of 普通钉钉用户账号开放
	 */

	/**
	 * start of 建立连接
	 */
	public function getAccessToken(){
		/**
         * 缓存accessToken。accessToken有效期为两小时，需要在失效前请求新的accessToken（注意：以下代码没有在失效前刷新缓存的accessToken）。
         */
        $accessToken = $this->getCache('corp_access_token');
        if ($accessToken == '' || $accessToken == false)
        {
            $corpid = $this->corpid;
            $corpsecret = $this->corpsecret;
            $response=$this->httpGet('gettoken',array('corpid'=>$corpid,'corpsecret'=>$corpsecret));
            if($response['errcode'] == 0){//正确返回
            	$accessToken = $response['access_token'];
            	$this->setCache('corp_access_token',$accessToken);
            }
        }
        return $accessToken;
	}
	/**
	 * end of 建立连接
	 */	
	/**
	 * start of 加密解密
	 */
	/**
	 * 加密初始化
	 */
	public function cryptInit($token, $encodingAesKey, $suiteKey)
	{
		$this->m_token = $token;
		$this->m_encodingAesKey = $encodingAesKey;
		$this->m_suiteKey = $suiteKey;
	}
	/**
     * 加密消息
     */
	public function EncryptMsg($plain, $timeStamp, $nonce, &$encryptMsg)
	{
		$pc = new Prpcrypt($this->m_encodingAesKey);

		$array = $pc->encrypt($plain, $this->m_suiteKey);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}

		if ($timeStamp == null) {
			$timeStamp = time();
		}
		$encrypt = $array[1];

		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_token, $timeStamp, $nonce, $encrypt);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}
		$signature = $array[1];

		$encryptMsg = json_encode(array(
			"msg_signature" => $signature,
			"encrypt" => $encrypt,
			"timeStamp" => $timeStamp,
			"nonce" => $nonce
		));
		return ErrorCode::$OK;
	}

	/**
	 * 解密消息
	 */
	public function DecryptMsg($signature, $timeStamp = null, $nonce, $encrypt, &$decryptMsg)
	{
		if (strlen($this->m_encodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->m_encodingAesKey);

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}

		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_token, $timeStamp, $nonce, $encrypt);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$verifySignature = $array[1];
		if ($verifySignature != $signature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($encrypt, $this->m_suiteKey);
		if ($result[0] != 0) {
			return $result[0];
		}
		$decryptMsg = $result[1];

		return ErrorCode::$OK;
	}
	/**
	 * end of 加密解密
	 */

	/**
	 * start of JS接口API
	 */
	public function getJsApiticket(){
		$jsticket= $this->getCache('js_api_ticket');
		if ($jsticket == '' || $jsticket == false)
        {
			$accessToken = $this->getAccessToken();
			$response=$this->httpGet('get_jsapi_ticket',array('access_token'=>$accessToken,'type'=>'jsapi'));
			if($response['errcode'] == 0){
				$jsticket = $response['ticket'];
				$this->setCache('js_api_ticket',$jsticket);
			}
		}
		return $jsticket;
	}
	/**
	 * end of JS接口API
	 */
	public function getCache($key=''){
		$cache_type = $this->cache_type;
		if('file'==$cache_type){
			//file library
			return $this->filecache->get($key,false,3600);//ttl 3600
		}elseif('redis'==$cache_type){
			//redis library

		}else{
			// system library
		}	
	}
	public function setCache($key='',$val){
		$cache_type = $this->cache_type;
		if('file'==$cache_type){
			//file library
			return $this->filecache->save($key,$val);
		}elseif('redis'==$cache_type){
			//redis library

		}else{
			// system library
		}
	}
	private function httpGet($url,$params=array()){
		$host = $this->host;
		$real_url = $host.'/'.$url;
		if(!empty($params)){
			$real_url .= '?';
			foreach ($params as $k => $val) {
				$real_url .= "$k=$val&";
			}
		}
		$real_url = rtrim($real_url,'&');
		// echo __line__.':'.$real_url;
		$result = file_get_contents($real_url);
		return json_decode($result,true);
	}
	private function httpPost($url,$params=array()){
		$host = $this->host;
		$real_url = $host.'/'.$url;
		// echo __line__.':'.$real_url;
        $this->curl->init();
        $data = json_encode($params, JSON_UNESCAPED_UNICODE);//参数json
       	// var_dump($data);
       	$this->curl->setHeaders(array('Content-Type'=>'application/json'));
        $result = $this->curl->post($real_url, $data);
        $this->curl->close();
        return json_decode($result, TRUE);
	}
	private function httpRawPost($url,$media=array()){
		$host = $this->host;
		$real_url = $host.'/'.$url;
		// echo __line__.':'.$real_url;
		$this->load->library('curl');
        $this->curl->init();
        @$this->curl->setHeaders(array('Content-Type'=>'multipart/form-data'));
        $result = $this->curl->post($real_url, $media);
        $this->curl->close();
        return json_decode($result, TRUE);
	}
	/**
     * 获取二进制头文件，从而得知属于什么类型文件
     * @param string $fileByte 二进制内容
     * @param string $filename 文件地址
     * @return  string
     */
    private function judge_file_type($fileByte = '', $filename = '')
    {
        if ($filename != '') {
            $file = fopen($filename, "rb");
            $bin = fread($file, 2); //只读2字节
            fclose($file);
        } else {
            $bin = substr($fileByte, 0, 2);
        }

        $strInfo = @unpack("C2chars", $bin);
        $typeCode = intval($strInfo['chars1'] . $strInfo['chars2']);

        switch ($typeCode) {
            case 3533:
                $fileType = 'amr';
                break;
            case 255216:
                $fileType = 'jpg';
                break;
            case 7173:
                $fileType = 'gif';
                break;
            case 13780:
                $fileType = 'png';
                break;
            case 7790:
                $fileType = 'exe';
                break;
            case 7784:
                $fileType = 'midi';
                break;
            case 8297:
                $fileType = 'rar';
                break;
            case 8075:
                $fileType = 'zip';
                break;
            case 6677:
                $fileType = 'bmp';
                break;
            default:
                $fileType = '';
                break;
        }

        //Fix
        if ($strInfo['chars1'] == '-1' AND $strInfo['chars2'] == '-40') return 'jpg';
        if ($strInfo['chars1'] == '-119' AND $strInfo['chars2'] == '80') return 'png';

        return $fileType;
    }
    private function sign($ticket, $nonceStr, $timeStamp, $url)
    {
        $plain = 'jsapi_ticket=' . $ticket .
            '&noncestr=' . $nonceStr .
            '&timestamp=' . $timeStamp .
            '&url=' . $url;
        return sha1($plain);
    }

}