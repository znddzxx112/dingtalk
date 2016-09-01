<?php 


/**
 * 文件缓存
 */
class Filecache
{
	/**
	 * 缓存根目录
	 * @var string
	 */
	public $root_dir = '';

	function __construct($conf='')
	{
		$this->root_dir = dirname(__file__);
		if($conf!=''){
			if(is_array($conf)){
				foreach ($conf as $k => $v) {
					isset($this->$k) && $this->$k = $v;
				}
			}
		}
	}

	public function save($key,$val){
		$dir = $this->root_dir;
		if(!is_dir($dir)){
			mkdir($dir,0764,true);	
		}
		$path = rtrim($dir,'/').'/'.$key;
		return file_put_contents($path, $val);
	}

	public function get($key, $is_persistent=true, $ttl=3600){
		$path = rtrim($this->root_dir,'/').'/'.$key;
		if(file_exists($path) ){
			if($is_persistent == false && filemtime($path) + $ttl <= time()){
				// 不持久 存在生命时间
				return false;
			}
			return file_get_contents($path);
		}else{
			return false;
		}
	}

}


