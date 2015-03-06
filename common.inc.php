<?php

/*
	[Discuz!] (C)2001-2007 Comsenz Inc.
	This is NOT a freeware, use is subject to license terms

	$Id: common.inc.php 11168 2007-11-08 05:23:57Z tiger $
*/
error_reporting(0);//屏蔽除了static级别的错误
set_magic_quotes_runtime(0);//屏蔽表单传参的过滤
$mtime = explode(' ', microtime());//空格切割unix时间戳和微秒数
$discuz_starttime = $mtime[1] + $mtime[0];//记录一个开始的时间戳

//定义一些discuz会用到的常量值
define('SYS_DEBUG', FALSE);//是否开启系统报错bug
define('IN_DISCUZ', TRUE);//代码运行范围，设置true后
// if (!defined('IN_DISCUZ')) {
// 在其他页面顶部调用这段代码就可以验证是否是非法入侵来的了
// 	exit('Access Denied');
// }
define('DISCUZ_ROOT', substr(dirname(__FILE__), 0, -7));//获得网站根目录路径
define('MAGIC_QUOTES_GPC', get_magic_quotes_gpc());//获取当前php运行环境是否启用过滤表单参数的值
!defined('CURSCRIPT') && define('CURSCRIPT', '');//获取CURSCRIPT的值，如果没有就将其定义为空

//验证php版本，主要是便于获取$_GET变量值的使用，不然就要使用$HTTP_变量值_VARS的方式获取变量值
if(PHP_VERSION < '4.1.0') {
	$_GET = &$HTTP_GET_VARS;
	$_POST = &$HTTP_POST_VARS;
	$_COOKIE = &$HTTP_COOKIE_VARS;
	$_SERVER = &$HTTP_SERVER_VARS;
	$_ENV = &$HTTP_ENV_VARS;
	$_FILES = &$HTTP_POST_FILES;
}

//验证脏数据使用
if (isset($_REQUEST['GLOBALS']) OR isset($_FILES['GLOBALS'])) {
	exit('Request tainting attempted.');
}

//根据根目录拼接引入程序自定义文件
require_once DISCUZ_ROOT.'./include/global.func.php';

//getrobot里设置了是否是搜索引擎来采集的，实现主要是根据HTTP_USER_AGENT用户代理判断是否是搜索引擎
define('ISROBOT', getrobot());

//验证NOROBOT是否是true，假如设置了NOROBOT为true，就返回403错误，禁止搜索引擎请求数据
if(defined('NOROBOT') && ISROBOT) {
	exit(header("HTTP/1.1 403 Forbidden"));
}

//遍历数组，过滤不是以"_"下划线开头的数据
foreach(array('_COOKIE', '_POST', '_GET') as $_request) {
	foreach($$_request as $_key => $_value) {
		$_key{0} != '_' && $$_key = daddslashes($_value);
	}
}

//再次判断是否是客户端提交过来的数据，是的话，就过滤
//MAGIC_QUOTES_GPC 开启了表单过滤
if (!MAGIC_QUOTES_GPC && $_FILES) {
	$_FILES = daddslashes($_FILES);
}

//初始化一些值
//$charset页面字符集编码
//$dbcharset数据库的字符集编码
//$metakeywords页面源代码中的Meta信息
//$extrahead页面中附加在<head>区域中的代码
//$seodescription页面对搜索引擎优化的信息
$charset = $dbcharset = $forumfounders = $metakeywords = $extrahead = $seodescription = '';

//初始化一些数组
//$plugins 是Discuz安装了插件的完整数据信息组
//$hooks 插件的钩子信息组
//$admincp 是config.inc.php中设置的部分配置信息组
//$jsmenu 是js菜单内容的信息组
//$language和$lang 是语言包的信息组
//$actioncode 是动作代码信息组
//$modactioncode 是操作动作代码信息组
$plugins = $hooks = $admincp = $jsmenu = $forum = $thread = $language = $actioncode = $modactioncode = $lang = array();

//引入discuz的配置文件
require_once DISCUZ_ROOT.'./config.inc.php';

//$_DCOOKIE 是Discuz自定义存放的Cookies信息的数组
//$_DSESSION 是Discuz自定义存放的Session信息的数组
//$_DCACHE 是Discuz自定义存放的系统缓存信息的数组
//$_DPLUGIN 是Discuz自定义存放的系统插件信息的数组
//$advlist 是Discuz自定义存放的广告信息的数组
$_DCOOKIE = $_DSESSION = $_DCACHE = $_DPLUGIN = $advlist = array();


//获取设置定的$cookiepre的cookies的前缀的长度
$prelength = strlen($cookiepre);
//遍历cookies，遍历项中的cookies前缀的长度同设置的cookies的前缀一致
//那么就根据MAGIC_QUOTES_GPC的值进行是否过滤，保存到Discuz自定义的cookies数组中去，$_DCOOKIE
foreach($_COOKIE as $key => $val) {
	if(substr($key, 0, $prelength) == $cookiepre) {
		$_DCOOKIE[(substr($key, $prelength))] = MAGIC_QUOTES_GPC ? $val : daddslashes($val);
	}
}
//销毁掉之前定义的参数
unset($prelength, $_request, $_key, $_value);

//验证当前操作是否涉及ajax效果
$inajax = !empty($inajax);
//获取unix时间戳赋值给$timestamp，这个$timestamp是Discuz中所有涉及Unix时间的地方所以需要的时间戳
$timestamp = time();

//验证是否启用了攻击防御，启用就引入security.inc.php文件，专门处理这种情况
if($attackevasive) {
	require_once DISCUZ_ROOT.'./include/security.inc.php';
}

//根据$database参数引入不同的数据库适配器文件，默认都是mysql
require_once DISCUZ_ROOT.'./include/db_'.$database.'.class.php';

//获取执行当前页面的名称带路径
$PHP_SELF = $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
//去除路径，只返回当前页面的名称
$BASESCRIPT = basename($PHP_SELF);
//$boardurl定义了访问当前Discuz安装副本的URL地址，如http://www.example.com/forum
$boardurl = htmlspecialchars('http://'.$_SERVER['HTTP_HOST'].preg_replace("/\/+(api|archiver|wap)?\/*$/i", '', substr($PHP_SELF, 0, strrpos($PHP_SELF, '/'))).'/');

//以下代码获取用户的IP值，通过不同的函数获取
if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
	$onlineip = getenv('HTTP_CLIENT_IP');
} elseif(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
	$onlineip = getenv('HTTP_X_FORWARDED_FOR');
} elseif(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
	$onlineip = getenv('REMOTE_ADDR');
} elseif(isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
	$onlineip = $_SERVER['REMOTE_ADDR'];
}

preg_match("/[\d\.]{7,15}/", $onlineip, $onlineipmatches);
$onlineip = $onlineipmatches[0] ? $onlineipmatches[0] : 'unknown';
unset($onlineipmatches);

$cachelost = (@include DISCUZ_ROOT.'./forumdata/cache/cache_settings.php') ? '' : 'settings';
@extract($_DCACHE['settings']);

if($gzipcompress && function_exists('ob_gzhandler') && CURSCRIPT != 'wap' && !$inajax) {
	ob_start('ob_gzhandler');
} else {
	$gzipcompress = 0;
	ob_start();
}

if(!empty($loadctrl) && substr(PHP_OS, 0, 3) != 'WIN') {
	if($fp = @fopen('/proc/loadavg', 'r')) {
		list($loadaverage) = explode(' ', fread($fp, 6));
		fclose($fp);
		if($loadaverage > $loadctrl) {
			header("HTTP/1.0 503 Service Unavailable");
			include DISCUZ_ROOT.'./include/serverbusy.htm';
			exit();
		}
	}
}

if(in_array(CURSCRIPT, array('index', 'forumdisplay', 'viewthread', 'post', 'blog', 'topicadmin', 'register', 'archiver'))) {
	$cachelost .= (@include DISCUZ_ROOT.'./forumdata/cache/cache_'.CURSCRIPT.'.php') ? '' : ' '.CURSCRIPT;
}

$db = new dbstuff;
$db->connect($dbhost, $dbuser, $dbpw, $dbname, $pconnect);
$dbuser = $dbpw = $dbname = $pconnect = NULL;

$sid = daddslashes(($transsidstatus || CURSCRIPT == 'wap') && (isset($_GET['sid']) || isset($_POST['sid'])) ?
	(isset($_GET['sid']) ? $_GET['sid'] : $_POST['sid']) :
	(isset($_DCOOKIE['sid']) ? $_DCOOKIE['sid'] : ''));

$discuz_auth_key = md5($_DCACHE['settings']['authkey'].$_SERVER['HTTP_USER_AGENT']);
list($discuz_pw, $discuz_secques, $discuz_uid) = empty($_DCOOKIE['auth']) ? array('', '', 0) : daddslashes(explode("\t", authcode($_DCOOKIE['auth'], 'DECODE')), 1);

$newpm = $newpmexists = $sessionexists = $seccode = $bloguid = 0;
$membertablefields = 'm.uid AS discuz_uid, m.username AS discuz_user, m.password AS discuz_pw, m.secques AS discuz_secques,
	m.adminid, m.groupid, m.groupexpiry, m.extgroupids, m.email, m.timeoffset, m.tpp, m.ppp, m.posts, m.digestposts,
	m.oltime, m.pageviews, m.credits, m.extcredits1, m.extcredits2, m.extcredits3, m.extcredits4, m.extcredits5,
	m.extcredits6, m.extcredits7, m.extcredits8, m.timeformat, m.dateformat, m.pmsound, m.sigstatus, m.invisible,
	m.lastvisit, m.lastactivity, m.lastpost, m.newpm, m.accessmasks, m.xspacestatus, m.editormode, m.customshow';
if($sid) {
	if($discuz_uid) {
		$query = $db->query("SELECT s.sid, s.styleid, s.groupid='6' AS ipbanned, s.pageviews AS spageviews, s.lastolupdate, s.seccode, $membertablefields
			FROM {$tablepre}sessions s, {$tablepre}members m
			WHERE m.uid=s.uid AND s.sid='$sid' AND CONCAT_WS('.',s.ip1,s.ip2,s.ip3,s.ip4)='$onlineip' AND m.uid='$discuz_uid'
			AND m.password='$discuz_pw' AND m.secques='$discuz_secques'");
	} else {
		$query = $db->query("SELECT sid, uid AS sessionuid, groupid, groupid='6' AS ipbanned, pageviews AS spageviews, styleid, lastolupdate, seccode
			FROM {$tablepre}sessions WHERE sid='$sid' AND CONCAT_WS('.',ip1,ip2,ip3,ip4)='$onlineip'");
	}
	if($_DSESSION = $db->fetch_array($query)) {
		$sessionexists = 1;
		if(!empty($_DSESSION['sessionuid'])) {
			$_DSESSION = array_merge($_DSESSION, $db->fetch_first("SELECT $membertablefields
				FROM {$tablepre}members m WHERE uid='$_DSESSION[sessionuid]'"));
		}
	} else {
		if($_DSESSION = $db->fetch_first("SELECT sid, groupid, groupid='6' AS ipbanned, pageviews AS spageviews, styleid, lastolupdate, seccode
			FROM {$tablepre}sessions WHERE sid='$sid' AND CONCAT_WS('.',ip1,ip2,ip3,ip4)='$onlineip'")) {
			clearcookies();
			$sessionexists = 1;
		}
	}
}

if(!$sessionexists) {
	if($discuz_uid) {
		if(!($_DSESSION = $db->fetch_first("SELECT $membertablefields, m.styleid
			FROM {$tablepre}members m WHERE m.uid='$discuz_uid' AND m.password='$discuz_pw' AND m.secques='$discuz_secques'"))) {
			clearcookies();
		}
	}

	if(ipbanned($onlineip)) $_DSESSION['ipbanned'] = 1;

	$_DSESSION['sid'] = random(6);
	$_DSESSION['seccode'] = random(6, 1);
}
$_DSESSION['dateformat'] = empty($_DSESSION['dateformat']) || empty($_DCACHE['settings']['userdateformat'][$_DSESSION['dateformat'] -1])? $_DCACHE['settings']['dateformat'] : $_DCACHE['settings']['userdateformat'][$_DSESSION['dateformat'] -1];
$_DSESSION['timeformat'] = empty($_DSESSION['timeformat']) ? $_DCACHE['settings']['timeformat'] : ($_DSESSION['timeformat'] == 1 ? 'h:i A' : 'H:i');
$_DSESSION['timeoffset'] = isset($_DSESSION['timeoffset']) && $_DSESSION['timeoffset'] != 9999 ? $_DSESSION['timeoffset'] : $_DCACHE['settings']['timeoffset'];

$membertablefields = '';
@extract($_DSESSION);

$lastvisit = empty($lastvisit) ? $timestamp - 86400 : $lastvisit;
$timenow = array('time' => gmdate("$dateformat $timeformat", $timestamp + 3600 * $timeoffset),
	'offset' => ($timeoffset >= 0 ? ($timeoffset == 0 ? '' : '+'.$timeoffset) : $timeoffset));

if(PHP_VERSION > '5.1') {
	@date_default_timezone_set('Etc/GMT'.($timeoffset > 0 ? '-' : '+').(abs($timeoffset)));
}

$accessadd1 = $accessadd2 = $modadd1 = $modadd2 = $metadescription = '';
if(empty($discuz_uid) || empty($discuz_user)) {
	$discuz_user = $extgroupids = '';
	$discuz_uid = $adminid = $posts = $digestposts = $pageviews = $oltime = $invisible
		= $credits = $extcredits1 = $extcredits2 = $extcredits3 = $extcredits4
		= $extcredits5 = $extcredits6 = $extcredits7 = $extcredits8 = 0;
	$groupid = empty($groupid) || $groupid != 6 ? 7 : 6;

} else {
	$discuz_userss = $discuz_user;
	$discuz_user = addslashes($discuz_user);

	if($accessmasks) {
		$accessadd1 = ', a.allowview, a.allowpost, a.allowreply, a.allowgetattach, a.allowpostattach';
		$accessadd2 = "LEFT JOIN {$tablepre}access a ON a.uid='$discuz_uid' AND a.fid=f.fid";
	}

	if($adminid == 3) {
		$modadd1 = ', m.uid AS ismoderator';
		$modadd2 = "LEFT JOIN {$tablepre}moderators m ON m.uid='$discuz_uid' AND m.fid=f.fid";
	}
}

if($errorreport == 2 || ($errorreport == 1 && $adminid > 0)) {
	error_reporting(E_ERROR | E_WARNING | E_PARSE);
}

define('FORMHASH', formhash());

$statstatus && !$inajax && require_once DISCUZ_ROOT.'./include/counter.inc.php';

$extra = isset($extra) && @preg_match("/^[&=;a-z0-9]+$/i", $extra) ? $extra : '';

$rsshead = $navtitle = $navigation = '';

$_DSESSION['groupid'] = $groupid = empty($ipbanned) ? (empty($groupid) ? 7 : intval($groupid)) : 6;
if(!@include DISCUZ_ROOT.'./forumdata/cache/usergroup_'.$groupid.'.php') {
	$grouptype = $db->result_first("SELECT type FROM {$tablepre}usergroups WHERE groupid='$groupid'");
	if(!empty($grouptype)) {
		$cachelost .= ' usergroup_'.$groupid;
	} else {
		$grouptype = 'member';
	}
}

if($passport_status && ($passport_status != 'shopex' || !$passport_shopex)) {
	$passport_forward = rawurlencode('http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
	$link_login = $passport_url.$passport_login_url.(strpos($passport_login_url, '?') === FALSE ? '?' : '&amp;').'forward='.$passport_forward;
	$link_logout = $passport_url.$passport_logout_url.(strpos($passport_logout_url, '?') === FALSE ? '?' : '&amp;').'forward='.$passport_forward;
	$link_register = $passport_url.$passport_register_url.(strpos($passport_register_url, '?') === FALSE ? '?' : '&amp;').'forward='.$passport_forward;
} else {
	$link_login = 'logging.php?action=login';
	$link_logout = 'logging.php?action=logout&amp;formhash='.FORMHASH;
	$link_register = $regname;
}

if($discuz_uid && $_DSESSION) {
	if(!empty($groupexpiry) && $groupexpiry < $timestamp && !in_array(CURSCRIPT, array('wap', 'member'))) {
		dheader("Location: {$boardurl}member.php?action=groupexpiry");
	} elseif($grouptype && $groupid != getgroupid($discuz_uid, array
		(
		'type' => $grouptype,
		'creditshigher' => $groupcreditshigher,
		'creditslower' => $groupcreditslower
		), $_DSESSION)) {
		@extract($_DSESSION);
		$cachelost .= (@include DISCUZ_ROOT.'./forumdata/cache/usergroup_'.intval($groupid).'.php') ? '' : ' usergroup_'.$groupid;
	}
}

$tpp = intval(empty($_DSESSION['tpp']) ? $topicperpage : $_DSESSION['tpp']);
$ppp = intval(empty($_DSESSION['ppp']) ? $postperpage : $_DSESSION['ppp']);

if(!in_array($adminid, array(1, 2, 3))) {
	$alloweditpost = $alloweditpoll = $allowstickthread = $allowmodpost = $allowdelpost = $allowmassprune
		= $allowrefund = $allowcensorword = $allowviewip = $allowbanip = $allowedituser = $allowmoduser
		= $allowbanuser = $allowpostannounce = $allowviewlog = $disablepostctrl = $supe_allowpushthread = 0;
} elseif(isset($radminid) && $adminid != $radminid && $adminid != $groupid) {
	$cachelost .= (@include DISCUZ_ROOT.'./forumdata/cache/admingroup_'.intval($adminid).'.php') ? '' : ' admingroup_'.$groupid;
}

$auditstatuson = !empty($mod) && $mod == 'edit' && in_array($adminid, array(1, 2, 3)) && $allowmodpost ? true : false;

$page = isset($page) ? max(1, intval($page)) : 1;
$tid = isset($tid) && is_numeric($tid) ? $tid : 0;
$fid = isset($fid) && is_numeric($fid) ? $fid : 0;
$typeid = isset($typeid) ? intval($typeid) : 0;

if(!empty($tid) || !empty($fid)) {
	if(empty($tid)) {
		$forum = $db->fetch_first("SELECT f.fid, f.*, ff.* $accessadd1 $modadd1, f.fid AS fid
			FROM {$tablepre}forums f
			LEFT JOIN {$tablepre}forumfields ff ON ff.fid=f.fid $accessadd2 $modadd2
			WHERE f.fid='$fid'");
	} else {
		$forum = $db->fetch_first("SELECT t.tid, t.closed,".(defined('SQL_ADD_THREAD') ? SQL_ADD_THREAD : '')." f.*, ff.* $accessadd1 $modadd1, f.fid AS fid
			FROM {$tablepre}threads t
			INNER JOIN {$tablepre}forums f ON f.fid=t.fid
			LEFT JOIN {$tablepre}forumfields ff ON ff.fid=f.fid $accessadd2 $modadd2
			WHERE t.tid='$tid'".($auditstatuson ? '' : " AND t.displayorder>='0'")." LIMIT 1");
		$tid = $forum['tid'];
	}

	if($forum) {
		$fid = $forum['fid'];
		$forum['ismoderator'] = !empty($forum['ismoderator']) || $adminid == 1 || $adminid == 2 ? 1 : 0;
		foreach(array('postcredits', 'replycredits', 'threadtypes', 'digestcredits', 'postattachcredits', 'getattachcredits', 'supe_pushsetting') as $key) {
			$forum[$key] = !empty($forum[$key]) ? unserialize($forum[$key]) : array();
		}
	} else {
		$fid = 0;
	}
}

$styleid = intval(!empty($_GET['styleid']) ? $_GET['styleid'] :
		(!empty($_POST['styleid']) ? $_POST['styleid'] :
		(!empty($_DSESSION['styleid']) ? $_DSESSION['styleid'] :
		$_DCACHE['settings']['styleid'])));

$styleid = intval(isset($stylejump[$styleid]) ? $styleid : $_DCACHE['settings']['styleid']);

if(@!include DISCUZ_ROOT.'./forumdata/cache/style_'.intval(!empty($forum['styleid']) ? $forum['styleid'] : $styleid).'.php') {
	$cachelost .= (@include DISCUZ_ROOT.'./forumdata/cache/style_'.($styleid = $_DCACHE['settings']['styleid']).'.php') ? '' : ' style_'.$styleid;
}

if($cachelost) {
	require_once DISCUZ_ROOT.'./include/cache.func.php';
	updatecache();
	exit('Cache List: '.$cachelost.'<br />Caches successfully created, please refresh.');
}

if(CURSCRIPT != 'wap') {
	if($nocacheheaders) {
		@dheader("Expires: 0");
		@dheader("Cache-Control: private, post-check=0, pre-check=0, max-age=0", FALSE);
		@dheader("Pragma: no-cache");
	}
	if($headercharset) {
		@dheader('Content-Type: text/html; charset='.$charset);
	}
	if(empty($_DCOOKIE['sid']) || $sid != $_DCOOKIE['sid']) {
		dsetcookie('sid', $sid, 604800);
	}
}

if(!empty($insenz['cronnextrun']) && $insenz['cronnextrun'] <= $timestamp) {
	require_once DISCUZ_ROOT.'./include/insenz_cron.func.php';
	insenz_runcron();
} elseif($cronnextrun && $cronnextrun <= $timestamp) {
	require_once DISCUZ_ROOT.'./include/cron.func.php';
	runcron();
} elseif(isset($insenz['statsnextrun']) && $insenz['statsnextrun'] <= $timestamp) {
	require_once DISCUZ_ROOT.'./include/insenz_cron.func.php';
	insenz_onlinestats();
}

if(isset($plugins['include']) && is_array($plugins['include'])) {
	foreach($plugins['include'] as $include) {
		if(!$include['adminid'] || ($include['adminid'] && $include['adminid'] >= $adminid)) {
			@include_once DISCUZ_ROOT.'./plugins/'.$include['script'].'.inc.php';
		}
	}
}

if((!empty($_DCACHE['advs']) || $globaladvs) && !defined('IN_ADMINCP')) {
	require_once DISCUZ_ROOT.'./include/advertisements.inc.php';
}

if(isset($allowvisit) && $allowvisit == 0 && !(CURSCRIPT == 'member' && ($action == 'groupexpiry' || $action == 'activate'))) {
	showmessage('user_banned', NULL, 'HALTED');
} elseif(!(in_array(CURSCRIPT, array('logging', 'wap', 'seccode')) || $adminid == 1)) {
	if($bbclosed) {
		clearcookies();
		$closedreason = $db->result_first("SELECT value FROM {$tablepre}settings WHERE variable='closedreason'");
		showmessage($closedreason ? $closedreason : 'board_closed', NULL, 'NOPERM');
	}
	periodscheck('visitbanperiods');
}

if((!empty($fromuid) || !empty($fromuser)) && ($creditspolicy['promotion_visit'] || $creditspolicy['promotion_register'])) {
	require_once DISCUZ_ROOT.'/include/promotion.inc.php';
}

$rssauth = $rssstatus && $discuz_uid ? rawurlencode(authcode("$discuz_uid\t".($fid ? $fid : '')."\t".substr(md5($discuz_pw.$discuz_secques), 0, 8), 'ENCODE', md5($_DCACHE['settings']['authkey']))) : '0';
$transferstatus = $transferstatus && $allowtransfer;

?>