<?php
/**
 * Wedge importer engine
 *
 * This file deals with importing data to wedge forum software.
 *
 * @package wedge importer
 * @copyright 2010-2011 Thorsten "TE" Eurich, wedge.org
 * @license http://wedge.org/license/
 *
 * @version 0.1
 */

// Buy some time
@set_time_limit(600);

//Try to set our error- and exception handlers.
@set_exception_handler(array('import_exception', 'exception_handler'));
@set_error_handler(array('import_exception', 'error_handler_callback'), E_ALL);

//Load the language file and create an importer cookie.
lng::loadLang();

$cookie = new Cookie();
$import = new Importer();
$template = new template();

//XML ajax feedback? We can just skip everything else
if (isset($_GET['xml']))
{
	$template->xml();
	die();
}

//UI and worker process comes next..
$template->header();

if (method_exists($import, 'doStep' . $_GET['step']))
	call_user_func(array($import, 'doStep' . $_GET['step']));

$template->footer();


/**
 * Object weimp creates the main XML object
 *
 */
class Importer
{
	const WEDGE = 'import';
	const INVALID_IP = '00000000000000000000000000000000';

	public $db;

	public $to_prefix;
	public $from_prefix;

	private $ignore = true;
	private $replace = false;

	public function __construct()
	{
		// Save here so it doesn't get overwritten when sessions are restarted.
		if (isset($_REQUEST['import_script']))
			$this->script = @$_REQUEST['import_script'];

		// Clean up after unfriendly php.ini settings.
		if (function_exists('set_magic_quotes_runtime') && version_compare(PHP_VERSION, '5.3.0') < 0)
			@set_magic_quotes_runtime(0);

		error_reporting(E_ALL);
		ignore_user_abort(true);
		umask(0);

		ob_start();

		// disable gzip compression if possible
		if (is_callable('apache_setenv'))
			apache_setenv('no-gzip', '1');

		if (@ini_get('session.save_handler') == 'user')
			@ini_set('session.save_handler', 'files');
		@session_start();

		// Add slashes, as long as they aren't already being added.
		if (function_exists('get_magic_quotes_gpc') && @get_magic_quotes_gpc() != 0)
			$_POST = helper::stripslashes_recursive($_POST);

		// This is really quite simple; if ?delete is on the URL, delete the importer...
		if (isset($_GET['delete']))
		{
			@unlink(dirname(__FILE__) . '/error_log');
			@unlink(__FILE__);
			if (preg_match('~_to_wedge\.xml$~', $_SESSION['import_script']) != 0)
				@unlink(dirname(__FILE__) . '/' . $_SESSION['import_script']);
			$_SESSION['import_script'] = null;

			exit;
		}
		// Empty the error log?
		if (isset($_REQUEST['empty_error_log']))
			@unlink(dirname(__FILE__) . '/error_log');

		// The current step - starts at 0.
		$_GET['step'] =  isset($_GET['step']) ? (int) @$_GET['step'] : 0;
		$_REQUEST['start'] = isset($_REQUEST['start']) ? (int) @$_REQUEST['start'] : 0;

		// Check for the password...
		if (isset($_POST['db_pass']))
			$_SESSION['import_db_pass'] = $_POST['db_pass'];
		elseif (isset($_SESSION['import_db_pass']))
			$_POST['db_pass'] = $_SESSION['import_db_pass'];

		if (isset($_SESSION['import_paths']) && !isset($_POST['path_from']) && !isset($_POST['path_to']))
			list ($_POST['path_from'], $_POST['path_to']) = $_SESSION['import_paths'];
		elseif (isset($_POST['path_from']) || isset($_POST['path_to']))
		{
			if (isset($_POST['path_from']))
				$_POST['path_from'] = substr($_POST['path_from'], -1) == '/' ? substr($_POST['path_from'], 0, -1) : $_POST['path_from'];
			if (isset($_POST['path_to']))
				$_POST['path_to'] = substr($_POST['path_to'], -1) == '/' ? substr($_POST['path_to'], 0, -1) : $_POST['path_to'];

			$_SESSION['import_paths'] = array(@$_POST['path_from'], @$_POST['path_to']);
		}

		// If we have our script then set it to the session.
		if (!empty($this->script))
			$_SESSION['import_script'] = (string) $this->script;
		if (isset($_SESSION['import_script']) && file_exists(dirname(__FILE__) . '/' . $_SESSION['import_script']) && preg_match('~_to_wedge\.xml$~', $_SESSION['import_script']) != 0)
			$this->preparse_xml(dirname(__FILE__) . '/' . $_SESSION['import_script']);
		else
			unset($_SESSION['import_script']);
	}

	private function preparse_xml($file)
	{
		try
		{
			if (!$this->xml = simplexml_load_file($file, 'SimpleXMLElement', LIBXML_NOCDATA))
				throw new import_exception('XML-Syntax error in file: ' . $file);

			$this->xml = simplexml_load_file($file, 'SimpleXMLElement', LIBXML_NOCDATA);
		}
		catch (Exception $e)
		{
			import_exception::exception_handler($e);
		}

		if (isset($_POST['path_to']) && !empty($_GET['step']))
			$this->loadSettings();
	}

	private function detect_scripts()
	{
		global $template;

		if (isset($_REQUEST['import_script']))
		{
			if ($_REQUEST['import_script'] != '' && preg_match('~^[a-z0-9\-_\.]*_to_wedge\.xml$~i', $_REQUEST['import_script']) != 0)
				$_SESSION['import_script'] = preg_replace('~[\.]+~', '.', $_REQUEST['import_script']);
			else
				$_SESSION['import_script'] = null;
		}

		$dir = dir(dirname(__FILE__));
		$scripts = array();
		while ($entry = $dir->read())
		{
			if (substr($entry, -13) != '_to_wedge.xml')
				continue;

			if (substr($entry, -13) == '_to_wedge.xml')
			{
				try
				{
					if (!$xmlObj = simplexml_load_file($entry, 'SimpleXMLElement', LIBXML_NOCDATA))
						throw new import_exception('XML-Syntax error in file: ' . $entry);

					$xmlObj = simplexml_load_file($entry, 'SimpleXMLElement', LIBXML_NOCDATA);
				}
				catch (Exception $e)
				{
					import_exception::exception_handler($e);
				}
				$scripts[] = array('path' => $entry, 'name' => $xmlObj->general->name);
			}
		}
		$dir->close();

		if (isset($_SESSION['import_script']))
		{
			if (count($scripts) > 1)
				$GLOBALS['possible_scripts'] = $scripts;
			return false;
		}

		if (count($scripts) == 1)
		{
			$_SESSION['import_script'] = basename($scripts[0]['path']);
			if (substr($_SESSION['import_script'], -4) == '.xml')
				$this->preparse_xml(dirname(__FILE__) . '/' . $_SESSION['import_script']);
			return false;
		}

		$template->select_script($scripts);

		return true;
	}

	private function loadSettings()
	{
		global $db, $template, $to_prefix;

		if ($this->xml->general->defines)
			foreach ($this->xml->general->defines as $define)
			{
				$define = explode('=', $define);
				define($define[0], isset($define[1]) ? $define[1] : '1');
			}

		if ($this->xml->general->globals)
		{
			foreach ($this->xml->general->globals as $global)
				global $$global;
		}

		if ($this->xml->general->form)
		{
			foreach ($this->xml->general->form->children() as $global)
				global $$global;
		}

		// Cannot find Settings.php?
		if (!file_exists($_POST['path_to'] . '/Settings.php'))
			return $this->doStep0(lng::get('we.imp.settings_not_found'));

		$found = empty($this->xml->general->settings);

		foreach ($this->xml->general->settings as $file)
			$found |= @file_exists($_POST['path_from'] . stripslashes($file));

		if (@ini_get('open_basedir') != '' && !$found)
			return $this->doStep0(array(lng::get('we.imp.open_basedir'), (string) $this->xml->general->name));

		if (!$found)
			return $this->doStep0(array(lng::get('we.imp.config_not_found'), (string) $this->xml->general->name));

		// Any custom form elements to speak of?
		if ($this->xml->general->form && !empty($_SESSION['import_parameters']))
		{
			foreach ($this->xml->general->form->children() as $param)
			{
				if (isset($_POST['field' . $param['id']]))
				{
					$var = (string) $param;
					$_SESSION['import_parameters']['field' .$param['id']][$var] = $_POST['field' .$param['id']];
				}
			}

			// Should already be global'd.
			foreach ($_SESSION['import_parameters'] as $id)
			{
				foreach ($id as $k => $v)
					$$k = $v;
			}
		}
		elseif ($this->xml->general->form)
		{
			$_SESSION['import_parameters'] = array();
			foreach ($this->xml->general->form->children() as $param)
			{
				$var = (string) $param;

				if (isset($_POST['field' .$param['id']]))
					$_SESSION['import_parameters']['field' .$param['id']][$var] = $_POST['field' .$param['id']];
				else
					$_SESSION['import_parameters']['field' .$param['id']][$var] = null;
			}

			foreach ($_SESSION['import_parameters'] as $id)
			{
				foreach ($id as $k => $v)
					$$k = $v;
			}
		}
		// Everything should be alright now... no cross server includes, we hope...
		require_once($_POST['path_to'] . '/Settings.php');
		$GLOBALS['boardurl'] = $boardurl;
		$this->boardurl = $boardurl;

		if ($_SESSION['import_db_pass'] != $db_passwd)
			return $this->doStep0(lng::get('we.imp.password_incorrect'), $this);

		// Check the steps that we have decided to go through.
		if (!isset($_POST['do_steps']) && !isset($_SESSION['do_steps']))
			return $this->doStep0(lng::get('we.imp.select_step'));

		elseif (isset($_POST['do_steps']))
		{
			unset($_SESSION['do_steps']);
			foreach ($_POST['do_steps'] as $key => $step)
				$_SESSION['do_steps'][$key] = $step;
		}
		try
		{
			$db = new Database($db_server, $db_user, $db_passwd, $db_persist);
			// Wedge is UTF8 only, let's set our mysql connetction to utf8
			$db->query('SET NAMES \'utf8\'');
		}
		catch(Exception $e)
		{
			import_exception::exception_handler($e);
			die();
		}

		if (strpos($db_prefix, '.') === false)
		{
			$this->to_prefix = is_numeric(substr($db_prefix, 0, 1)) ? $db_name . '.' . $db_prefix : '`' . $db_name . '`.' . $db_prefix;
			$to_prefix = is_numeric(substr($db_prefix, 0, 1)) ? $db_name . '.' . $db_prefix : '`' . $db_name . '`.' . $db_prefix;
		}
		else
		{
			$to_prefix = $db_prefix;
			$this->to_prefix = $db_prefix;
		}
		if (isset($this->xml->general->custom_functions))
			eval($this->xml->general->custom_functions);

		if (isset($this->xml->general->variables))
		{
			foreach ($this->xml->general->variables as $eval_me)
				eval($eval_me);
		}

		if (isset($this->xml->general->settings))
		{
			foreach ($this->xml->general->settings as $file)
			{
				if (file_exists($_POST['path_from'] . $file))
					require_once($_POST['path_from'] . $file);
			}
		}

		if (isset($this->xml->general->from_prefix))
		{
			$from_prefix = eval('return "' . $this->xml->general->from_prefix . '";');
			$this->from_prefix = eval('return "' . $this->xml->general->from_prefix . '";');
		}
		if (preg_match('~^`[^`]+`.\d~', $this->from_prefix) != 0)
		{
			$from_prefix = strtr($from_prefix, array('`' => ''));
			$this->from_prefix = strtr($this->from_prefix, array('`' => ''));
		}

		if ($_REQUEST['start'] == 0 && empty($_GET['substep']) && ($_GET['step'] == 1 || $_GET['step'] == 2) && isset($this->xml->general->table_test))
		{
			$result = $db->query("
				SELECT COUNT(*)
				FROM " . eval('return "' . $this->xml->general->table_test . '";'), true);
			if ($result === false)
				$this->doStep0(lng::get('we.imp.permission_denied') . mysql_error(), (string) $this->xml->general->name);

			$db->free_result($result);
		}

		$results = $db->query("SELECT @@SQL_BIG_SELECTS, @@SQL_MAX_JOIN_SIZE");
		list ($big_selects, $sql_max_join) = $db->fetch_row($results);

		// Only waste a query if its worth it.
		if (empty($big_selects) || ($big_selects != 1 && $big_selects != '1'))
			$db->query("SET @@SQL_BIG_SELECTS = 1");

		// Lets set MAX_JOIN_SIZE to something we should
		if (empty($sql_max_join) || ($sql_max_join == '18446744073709551615' && $sql_max_join == '18446744073709551615'))
			$db->query("SET @@SQL_MAX_JOIN_SIZE = 18446744073709551615");
	}

	// Looks at the importer and returns the steps that it's able to make.
	private function find_steps()
	{
		$steps = array();
		$steps_count = 0;

		foreach ($this->xml->step as $xml_steps)
		{
			$steps_count++;

			$steps[$steps_count] = array(
				'name' => (string) $xml_steps->title,
				'count' => $steps_count,
				'mandatory' => $xml_steps->attributes()->{'type'},
			);
		}
		return $steps;
	}

	private function fix_params($string)
	{
		if (isset($_SESSION['import_parameters']))
		{
			foreach ($_SESSION['import_parameters'] as $param)
			{
				foreach ($param as $key => $value)
					$string = strtr($string, array('{$' . $key . '}' => $value));
			}
		}
		$string = strtr($string, array('{$from_prefix}' => $this->from_prefix, '{$to_prefix}' => $this->to_prefix));

		return $string;
	}
	/**
	* Converts an IP address from either IPv4, or IPv6 form into the 32 hexdigit string used internally.
	* function taken from the Wedge core (QueryString.php).
	*
	* @param string $ip An IP address in IPv4 (x.y.z.a), IPv4 over IPv6 (::ffff:x.y.z.a) or IPv6 (x:y:z:a::b) type formats
	* @return string A 32 hexcharacter string, all 0 if the incoming address was not valid.
	*/
	private function expand_ip($ip)
	{
		static $ip_array = array();
		if (isset($ip_array[$ip]))
			return $ip_array[$ip];

		// OK, so what are we dealing with?
		$contains_v4 = strpos($ip, '.') !== false;
		$contains_v6 = strpos($ip, ':') !== false;

		if ($contains_v4)
		{
			// So it's IPv4 in some form. Is it x.y.z.a or ::ffff:x.y.z.a ?
			if ($contains_v6)
			{
				// OK, so it's probably ::ffff:x.y.z.a format, let's do something about that.
				if (strpos($ip, '::ffff:') !== 0)
					return self::INVALID_IP; // oops, it wasn't valid since this is the only valid prefix for this format.
				$ip = substr($ip, 7);
			}

			if (!preg_match('~^((([1]?\d)?\d|2[0-4]\d|25[0-5])\.){3}(([1]?\d)?\d|2[0-4]\d|25[0-5])$~', $ip))
				return self::INVALID_IP; // oops, not a valid IPv4 either

			// It's just x.y.z.a
			$ipv6 = '00000000000000000000ffff';
			$ipv4 = explode('.', $ip);
			foreach ($ipv4 as $octet)
				$ipv6 .= str_pad(dechex($octet), 2, '0', STR_PAD_LEFT);
			return $ip_array[$ip] = $ipv6;
		}
		elseif ($contains_v6)
		{
			if (strpos($ip, '::') !== false)
			{
				$pieces = explode('::', $ip);
				if (count($pieces) !== 2)
					return self::INVALID_IP; // can't be valid!

				// OK, so how many blocks do we have that are actual blocks?
				$before_pieces = explode(':', $pieces[0]);
				$after_pieces = explode(':', $pieces[1]);
				foreach ($before_pieces as $k => $v)
					if ($v == '')
						unset($before_pieces[$k]);
				foreach ($after_pieces as $k => $v)
					if ($v == '')
						unset($after_pieces[$k]);
				// Glue everything back together.
				$ip = preg_replace('~((?<!\:):$)~', '', $pieces[0] . (count($before_pieces) ? ':' : '') . str_repeat('0:', 8 - (count($before_pieces) + count($after_pieces))) . $pieces[1]);
			}

			$ipv6 = explode(':', $ip);
			foreach ($ipv6 as $k => $v)
				$ipv6[$k] = str_pad($v, 4, '0', STR_PAD_LEFT);
			return $ip_array[$ip] = implode('', $ipv6);
		}

		// Just in case we don't know what this is, return *something* (if it contains neither IPv4 nor IPv6, bye)
		return self::INVALID_IP;
	}

	public function doStep0($error_message = null, $object = false)
	{
		global $db, $template, $to_prefix, $import_script, $cookie, $import;

		$import = isset($object) ? $object : false;
		$cookie -> destroy();
		unset($_SESSION['import_steps']);

		if ($this->detect_scripts())
			return true;

		// If these aren't set (from an error..) default to the current directory.
		if (!isset($_POST['path_from']))
			$_POST['path_from'] = dirname(__FILE__);
		if (!isset($_POST['path_to']))
			$_POST['path_to'] = dirname(__FILE__);

		$test_from = empty($this->xml->general->settings);

		foreach ($this->xml->general->settings as $s)
			$test_from |= @file_exists($_POST['path_from'] . $s);

		$test_to = @file_exists($_POST['path_to'] . '/Settings.php');

		// Was an error message specified?
		if ($error_message !== null)
		{
			$template = new template();
			$template->header(false);
			$template->error($error_message);
		}

		$template->step0($this, $this->find_steps(), $test_from, $test_to);

		if ($error_message !== null)
		{
			$template->footer();
			exit;
		}

		return;
	}

	public function doStep1()
	{
		global $db, $template, $cookie, $to_prefix;

		if ($this->xml->general->globals)
		{
			foreach ($this->xml->general->globals as $global)
			global $$global;
		}

		$cookie -> set(array($_POST['path_to'], $_POST['path_from']));
		$current_data = '';
		$substep = 0;
		$special_table = null;
		$special_code = null;
		$_GET['substep'] = isset($_GET['substep']) ? (int) @$_GET['substep'] : 0;

		// Skipping steps?
		if (isset($_SESSION['do_steps']))
			$do_steps = $_SESSION['do_steps'];

		foreach ($this->xml->step as $steps)
		{
			// Reset some defaults
			$current_data = '';
			$special_table = null;
			$special_code = null;

			// Increase the substep slightly...
			helper::pastTime(++$substep);

			$_SESSION['import_steps'][$substep]['title'] = (string) $steps->title;
			if (!isset($_SESSION['import_steps'][$substep]['status']))
				$_SESSION['import_steps'][$substep]['status'] = 0;

			// any preparsing code here?
			if (isset($steps->preparsecode) && !empty($steps->preparsecode))
				$special_code = $this->fix_params((string) $steps->preparsecode);

			$do_current = $substep >= $_GET['substep'];

			if (!in_array($substep, $do_steps))
			{
				$_SESSION['import_steps'][$substep]['status'] = 2;
				$_SESSION['import_steps'][$substep]['presql'] = true;
			}

			elseif ($steps->detect)
			{
				$count = $this->fix_params((string) $steps->detect);
				$table_test = $db->query("
					SELECT COUNT(*)
					FROM $count", true);

				if ($table_test === false)
				{
					$_SESSION['import_steps'][$substep]['status'] = 3;
					$_SESSION['import_steps'][$substep]['presql'] = true;
				}
			}

			$template->status($substep, $_SESSION['import_steps'][$substep]['status'], $_SESSION['import_steps'][$substep]['title']);

			// do we need to skip this step?
			if ($table_test === false || !in_array($substep, $do_steps))
			{
				// reset some defaults
				$current_data = '';
				$special_table = null;
				$special_code = null;
				continue;
			}

			// pre sql queries first!!
			if (isset($steps->presql) && !isset($_SESSION['import_steps'][$substep]['presql']))
			{
				$presql = $this->fix_params((string) $steps->presql);
				$presql_array = explode(';', $presql);
				if (isset($presql_array) && is_array($presql_array))
				{
					array_pop($presql_array);
					foreach ($presql_array as $exec)
						$db->query($exec . ';');
				}
				else
					$db->query($presql);
				// don't do this twice..
				$_SESSION['import_steps'][$substep]['presql'] = true;
			}

			if ($special_table === null)
			{
				$special_table = strtr(trim((string) $steps->destination), array('{$to_prefix}' => $this->to_prefix));
				$special_limit = 500;
			}
			else
				$special_table = null;

			if (isset($steps->query))
				$current_data = substr(rtrim($this->fix_params((string) $steps->query)), 0, -1);

			if (isset($steps->options->limit))
				$special_limit = $steps->options->limit;

			if (!$do_current)
			{
				$current_data = '';
				continue;
			}

			// codeblock?
			if (isset($steps->code))
			{
				// execute our code block
				$special_code = $this->fix_params((string) $steps->code);
				eval($special_code);
				// reset some defaults
				$current_data = '';
				$special_table = null;
				$special_code = null;
				if ($_SESSION['import_steps'][$substep]['status'] == 0)
					$template->status($substep, 1, false, true);
				$_SESSION['import_steps'][$substep]['status'] = 1;
				flush();
				continue;
			}

			// sql block?
			if (!empty($steps->query))
			{
				if (strpos($current_data, '{$') !== false)
					$current_data = eval('return "' . addcslashes($current_data, '\\"') . '";');

				if (isset($steps->detect))
				{
					$count = $this->fix_params((string) $steps->detect);
					$result2 = $db->query("
						SELECT COUNT(*)
						FROM $count");
					list ($counter) = $db->fetch_row($result2);
					$this->count->$substep = $counter;
					$db->free_result($result2);
				}

				// create some handy shortcuts
				$ignore = (isset($steps->options->ignore) && $steps->options->ignore == true && !isset($steps->options->replace)) ? true : false;
				$replace = (isset($steps->options->replace) && $steps->options->replace == true) ? true : false;
				$no_add = (isset($steps->options->no_add) && $steps->options->no_add == true) ? true : false;
				$ignore_slashes = (isset($steps->options->ignore_slashes) && $steps->options->ignore_slashes == true) ? true : false;

				if (isset($import_table) && $import_table !== null && strpos($current_data, '%d') !== false)
				{
					preg_match('~FROM [(]?([^\s,]+)~i', (string) $steps->detect, $match);
					if (!empty($match))
					{
						$result = $db->query("
							SELECT COUNT(*)
							FROM $match[1]");
						list ($special_max) = $db->fetch_row($result);
						$db->free_result($result);
					}
					else
						$special_max = 0;
				}
				else
					$special_max = 0;

				if ($special_table === null)
					$db->query($current_data);

				else
				{
					// Are we doing attachments?  They're going to want a few things...
					if ($special_table == $this->to_prefix . 'attachments')
					{
						if (!isset($id_attach, $attachmentUploadDir))
						{
							$result = $db->query("
								SELECT MAX(id_attach) + 1
								FROM {$to_prefix}attachments");
							list ($id_attach) = $db->fetch_row($result);
							$db->free_result($result);

							$result = $db->query("
								SELECT value
								FROM {$to_prefix}settings
								WHERE variable = 'attachmentUploadDir'
								LIMIT 1");
							list ($attachmentUploadDir) = $db->fetch_row($result);
							$db->free_result($result);

							if (empty($id_attach))
								$id_attach = 1;
						}
					}
					while (true)
					{
						helper::pastTime($substep);

						if (strpos($current_data, '%d') !== false)
							$special_result = $db->query(sprintf($current_data, $_REQUEST['start'], $_REQUEST['start'] + $special_limit - 1) . "\n" . 'LIMIT ' . $special_limit);
						else
							$special_result = $db->query($current_data . "\n" . 'LIMIT ' . $_REQUEST['start'] . ', ' . $special_limit);

						$rows = array();
						$keys = array();

						while ($row = $db->fetch_assoc($special_result))
						{
							if ($special_code !== null)
								eval($special_code);

							// Here we have various bits of custom code for some known problems global to all importers.
							if ($special_table == $this->to_prefix . 'members')
							{
								// Let's ensure there are no illegal characters.
								$row['member_name'] = preg_replace('/[<>&"\'=\\\]/is', '', $row['member_name']);
								$row['real_name'] = trim($row['real_name'], " \t\n\r\x0B\0\xA0");

								if (strpos($row['real_name'], '<') !== false || strpos($row['real_name'], '>') !== false || strpos($row['real_name'], '& ') !== false)
									$row['real_name'] = htmlspecialchars($row['real_name'], ENT_QUOTES);
								else
									$row['real_name'] = strtr($row['real_name'], array('\'' => '&#039;'));
							}

							// prepare ip address conversion
							if (isset($this->xml->general->ip_to_ipv6))
							{
								$convert_ips = explode(',', $this->xml->general->ip_to_ipv6);
								foreach ($convert_ips as $ip)
								{
									$ip = trim($ip);
									if (array_key_exists($ip, $row))
										$row[$ip] = $this->expand_ip($row[$ip]);
								}
							}
							// prepare ip address conversion to a pointer
							if (isset($this->xml->general->ip_to_pointer))
							{
								$ips_to_pointer = explode(',', $this->xml->general->ip_to_pointer);
								foreach ($ips_to_pointer as $ip)
								{
									$ip = trim($ip);
									if (array_key_exists($ip, $row))
									{
										$ipv6ip = $this->expand_ip($row[$ip]);
										
										$request2 = $db->query("
											SELECT id_ip
											FROM {$to_prefix}log_ips
											WHERE member_ip = '" . $ipv6ip . "'
											LIMIT 1");
										//ip already  known?
										if ($db->num_rows($request2) != 0)
										{
											list ($id_ip) = $db->fetch_row($request2);
											$row[$ip] = $id_ip;
										}
										// insert the new ip
										else
										{
											$db->query("
												INSERT INTO {$to_prefix}log_ips
													(member_ip)
												VALUES ('$ipv6ip')");
											$pointer = $db->insert_id();
											$row[$ip] = $pointer;
										}
	
										$db->free_result($request2);
									}
								}
							}
							// inject our charset class, we need proper utf-8
							$row = Charset::fix($row);

							// If we have a message here, we'll want to convert <br /> to <br>.
							if (isset($row['body']))
								$row['body'] = str_replace(array(
										'<br />', '&#039;', '&#39;', '&quot;'
									), array(
										'<br>', '\'', '\'', '"'
									), $row['body']
								);

							if (empty($no_add) && empty($ignore_slashes))
								$rows[] = "'" . implode("', '", helper::addslashes_recursive($row)) . "'";
							elseif (empty($no_add) && !empty($ignore_slashes))
								$rows[] = "'" . implode("', '", $row) . "'";
							else
								$no_add = false;

							if (empty($keys))
								$keys = array_keys($row);
						}

						$insert_ignore = (isset($ignore) && $ignore == true && !isset($ignore)) ? 'IGNORE' : '';
						$insert_replace = (isset($replace) && $replace == true) ? 'REPLACE' : 'INSERT';

						if (!empty($rows))
							$db->query("
								$insert_replace $insert_ignore INTO $special_table
									(" . implode(', ', $keys) . ")
								VALUES (" . implode('),
									(', $rows) . ")");
						$_REQUEST['start'] += $special_limit;
						if (empty($special_max) && $db->num_rows($special_result) < $special_limit)
							break;
						elseif (!empty($special_max) && $db->num_rows($special_result) == 0 && $_REQUEST['start'] > $special_max)
							break;
						$db->free_result($special_result);
					}
				}
				$_REQUEST['start'] = 0;
				$special_code = null;
				$current_data = '';
			}
			if ($_SESSION['import_steps'][$substep]['status'] == 0)
				$template->status($substep, 1, false, true);

			$_SESSION['import_steps'][$substep]['status'] = 1;
			flush();
		}

		$_GET['substep'] = 0;
		$_REQUEST['start'] = 0;

		return $this->doStep2();
	}

	public function doStep2()
	{
		global $db, $template, $to_prefix;

		$_GET['step'] = '2';

		$template->step2();

		if ($_GET['substep'] <= 0)
		{
			// Get all members with wrong number of personal messages.
			$request = $db->query("
				SELECT mem.id_member, COUNT(pmr.id_pm) AS real_num, mem.instant_messages
				FROM {$to_prefix}members AS mem
					LEFT JOIN {$to_prefix}pm_recipients AS pmr ON (mem.id_member = pmr.id_member AND pmr.deleted = 0)
				GROUP BY mem.id_member
				HAVING real_num != instant_messages");
			while ($row = $db->fetch_assoc($request))
			{
				$db->query("
					UPDATE {$to_prefix}members
					SET instant_messages = $row[real_num]
					WHERE id_member = $row[id_member]
					LIMIT 1");

				helper::pastTime(0);
			}
			$db->free_result($request);

			$request = $db->query("
				SELECT mem.id_member, COUNT(pmr.id_pm) AS real_num, mem.unread_messages
				FROM {$to_prefix}members AS mem
					LEFT JOIN {$to_prefix}pm_recipients AS pmr ON (mem.id_member = pmr.id_member AND pmr.deleted = 0 AND pmr.is_read = 0)
				GROUP BY mem.id_member
				HAVING real_num != unread_messages");
			while ($row = $db->fetch_assoc($request))
			{
				$db->query("
					UPDATE {$to_prefix}members
					SET unread_messages = $row[real_num]
					WHERE id_member = $row[id_member]
					LIMIT 1");

				helper::pastTime(0);
			}
			$db->free_result($request);

			helper::pastTime(1);
		}

		if ($_GET['substep'] <= 1)
		{
			$request = $db->query("
				SELECT id_board, MAX(id_msg) AS id_last_msg, MAX(modified_time) AS last_edited
				FROM {$to_prefix}messages
				GROUP BY id_board");
			$modifyData = array();
			$modifyMsg = array();
			while ($row = $db->fetch_assoc($request))
			{
				$db->query("
					UPDATE {$to_prefix}boards
					SET id_last_msg = $row[id_last_msg], id_msg_updated = $row[id_last_msg]
					WHERE id_board = $row[id_board]
					LIMIT 1");
				$modifyData[$row['id_board']] = array(
					'last_msg' => $row['id_last_msg'],
					'last_edited' => $row['last_edited'],
				);
				$modifyMsg[] = $row['id_last_msg'];
			}
			$db->free_result($request);

			// Are there any boards where the updated message is not the last?
			if (!empty($modifyMsg))
			{
				$request = $db->query("
					SELECT id_board, id_msg, modified_time, poster_time
					FROM {$to_prefix}messages
					WHERE id_msg IN (" . implode(',', $modifyMsg) . ")");
				while ($row = $db->fetch_assoc($request))
				{
					// Have we got a message modified before this was posted?
					if (max($row['modified_time'], $row['poster_time']) < $modifyData[$row['id_board']]['last_edited'])
					{
						// Work out the ID of the message (This seems long but it won't happen much.
						$request2 = $db->query("
							SELECT id_msg
							FROM {$to_prefix}messages
							WHERE modified_time = " . $modifyData[$row['id_board']]['last_edited'] . "
							LIMIT 1");
						if ($db->num_rows($request2) != 0)
						{
							list ($id_msg) = $db->fetch_row($request2);

							$db->query("
								UPDATE {$to_prefix}boards
								SET id_msg_updated = $id_msg
								WHERE id_board = $row[id_board]
								LIMIT 1");
						}
						$db->free_result($request2);
					}
				}
				$db->free_result($request);
			}

			helper::pastTime(2);
		}

		if ($_GET['substep'] <= 2)
		{
			$request = $db->query("
				SELECT id_group
				FROM {$to_prefix}membergroups
				WHERE min_posts = -1");
			$all_groups = array();
			while ($row = $db->fetch_assoc($request))
				$all_groups[] = $row['id_group'];
			$db->free_result($request);

			$request = $db->query("
				SELECT id_board, member_groups
				FROM {$to_prefix}boards
				WHERE FIND_IN_SET(0, member_groups)");
			while ($row = $db->fetch_assoc($request))
				$db->query("
					UPDATE {$to_prefix}boards
					SET member_groups = '" . implode(',', array_unique(array_merge($all_groups, explode(',', $row['member_groups'])))) . "'
					WHERE id_board = $row[id_board]
					LIMIT 1");
			$db->free_result($request);

			helper::pastTime(3);
		}

		if ($_GET['substep'] <= 3)
		{
			// Get the number of messages...
			$result = $db->query("
				SELECT COUNT(*) AS totalMessages, MAX(id_msg) AS maxMsgID
				FROM {$to_prefix}messages");
			$row = $db->fetch_assoc($result);
			$db->free_result($result);

			// Update the latest member. (Highest ID_MEMBER)
			$result = $db->query("
				SELECT id_member AS latestMember, real_name AS latestreal_name
				FROM {$to_prefix}members
				ORDER BY id_member DESC
				LIMIT 1");
			if ($db->num_rows($result))
				$row += $db->fetch_assoc($result);
			$db->free_result($result);

			// Update the member count.
			$result = $db->query("
				SELECT COUNT(*) AS totalMembers
				FROM {$to_prefix}members");
			$row += $db->fetch_assoc($result);
			$db->free_result($result);

			// Get the number of topics.
			$result = $db->query("
				SELECT COUNT(*) AS totalTopics
				FROM {$to_prefix}topics");
			$row += $db->fetch_assoc($result);
			$db->free_result($result);

			$db->query("
				REPLACE INTO {$to_prefix}settings
					(variable, value)
				VALUES ('latestMember', '$row[latestMember]'),
					('latestreal_name', '$row[latestreal_name]'),
					('totalMembers', '$row[totalMembers]'),
					('totalMessages', '$row[totalMessages]'),
					('maxMsgID', '$row[maxMsgID]'),
					('totalTopics', '$row[totalTopics]'),
					('disableHashTime', " . (time() + 7776000) . ")");

			helper::pastTime(4);
		}

		if ($_GET['substep'] <= 4)
		{
			$request = $db->query("
				SELECT id_group, min_posts
				FROM {$to_prefix}membergroups
				WHERE min_posts != -1
				ORDER BY min_posts DESC");
			$post_groups = array();
			while ($row = $db->fetch_assoc($request))
				$post_groups[$row['min_posts']] = $row['id_group'];
			$db->free_result($request);

			$request = $db->query("
				SELECT id_member, posts
				FROM {$to_prefix}members");
			$mg_updates = array();
			while ($row = $db->fetch_assoc($request))
			{
				$group = 4;
				foreach ($post_groups as $min_posts => $group_id)
					if ($row['posts'] >= $min_posts)
					{
						$group = $group_id;
						break;
					}

				$mg_updates[$group][] = $row['id_member'];
			}
			$db->free_result($request);

			foreach ($mg_updates as $group_to => $update_members)
				$db->query("
					UPDATE {$to_prefix}members
					SET id_post_group = $group_to
					WHERE id_member IN (" . implode(', ', $update_members) . ")
					LIMIT " . count($update_members));

			helper::pastTime(5);
		}

		if ($_GET['substep'] <= 5)
		{
			// Needs to be done separately for each board.
			$result_boards = $db->query("
				SELECT id_board
				FROM {$to_prefix}boards");
			$boards = array();
			while ($row_boards = $db->fetch_assoc($result_boards))
				$boards[] = $row_boards['id_board'];
			$db->free_result($result_boards);

			foreach ($boards as $id_board)
			{
				// Get the number of topics, and iterate through them.
				$result_topics = $db->query("
					SELECT COUNT(*)
					FROM {$to_prefix}topics
					WHERE id_board = $id_board");
				list ($num_topics) = $db->fetch_row($result_topics);
				$db->free_result($result_topics);

				// Find how many messages are in the board.
				$result_posts = $db->query("
					SELECT COUNT(*)
					FROM {$to_prefix}messages
					WHERE id_board = $id_board");
				list ($num_posts) = $db->fetch_row($result_posts);
				$db->free_result($result_posts);

				// Fix the board's totals.
				$db->query("
					UPDATE {$to_prefix}boards
					SET num_topics = $num_topics, num_posts = $num_posts
					WHERE id_board = $id_board
					LIMIT 1");
			}

			helper::pastTime(6);
		}

		// Remove all topics that have zero messages in the messages table.
		if ($_GET['substep'] <= 6)
		{
			while (true)
			{
				$resultTopic = $db->query("
					SELECT t.id_topic, COUNT(m.id_msg) AS num_msg
					FROM {$to_prefix}topics AS t
						LEFT JOIN {$to_prefix}messages AS m ON (m.id_topic = t.id_topic)
					GROUP BY t.id_topic
					HAVING num_msg = 0
					LIMIT $_REQUEST[start], 200");

				$numRows = $db->num_rows($resultTopic);

				if ($numRows > 0)
				{
					$stupidTopics = array();
					while ($topicArray = $db->fetch_assoc($resultTopic))
						$stupidTopics[] = $topicArray['id_topic'];
					$db->query("
						DELETE FROM {$to_prefix}topics
						WHERE id_topic IN (" . implode(',', $stupidTopics) . ')
						LIMIT ' . count($stupidTopics));
					$db->query("
						DELETE FROM {$to_prefix}log_topics
						WHERE id_topic IN (" . implode(',', $stupidTopics) . ')');
				}
				$db->free_result($resultTopic);

				if ($numRows < 200)
					break;

				$_REQUEST['start'] += 200;
				helper::pastTime(6);
			}

			$_REQUEST['start'] = 0;
			helper::pastTime(7);
		}

		// Get the correct number of replies.
		if ($_GET['substep'] <= 7)
		{
			while (true)
			{
				$resultTopic = $db->query("
					SELECT
						t.id_topic, MIN(m.id_msg) AS myid_first_msg, t.id_first_msg,
						MAX(m.id_msg) AS myid_last_msg, t.id_last_msg, COUNT(m.id_msg) - 1 AS my_num_replies,
						t.num_replies
					FROM {$to_prefix}topics AS t
						LEFT JOIN {$to_prefix}messages AS m ON (m.id_topic = t.id_topic)
					GROUP BY t.id_topic
					HAVING id_first_msg != myid_first_msg OR id_last_msg != myid_last_msg OR num_replies != my_num_replies
					LIMIT $_REQUEST[start], " . (!empty($convert_data['step2_block_size']) ? $convert_data['step2_block_size'] : 200));

				$numRows = $db->num_rows($resultTopic);

				while ($topicArray = $db->fetch_assoc($resultTopic))
				{
					$memberStartedID = helper::getMsgMemberID($topicArray['myid_first_msg']);
					$memberUpdatedID = helper::getMsgMemberID($topicArray['myid_last_msg']);

					$db->query("
						UPDATE {$to_prefix}topics
						SET id_first_msg = '$topicArray[myid_first_msg]',
							id_member_started = '$memberStartedID', id_last_msg = '$topicArray[myid_last_msg]',
							id_member_updated = '$memberUpdatedID', num_replies = '$topicArray[my_num_replies]'
						WHERE id_topic = $topicArray[id_topic]
						LIMIT 1");
				}
				$db->free_result($resultTopic);

				if ($numRows < 200)
					break;

				$_REQUEST['start'] += 100;
				helper::pastTime(7);
			}

			$_REQUEST['start'] = 0;
			helper::pastTime(8);
		}

		// Fix id_cat, id_parent, and child_level.
		if ($_GET['substep'] <= 8)
		{
			// First, let's get an array of boards and parents.
			$request = $db->query("
				SELECT id_board, id_parent, id_cat
				FROM {$to_prefix}boards");
			$child_map = array();
			$cat_map = array();
			while ($row = $db->fetch_assoc($request))
			{
				$child_map[$row['id_parent']][] = $row['id_board'];
				$cat_map[$row['id_board']] = $row['id_cat'];
			}
			$db->free_result($request);

			// Let's look for any boards with obviously invalid parents...
			foreach ($child_map as $parent => $dummy)
			{
				if ($parent != 0 && !isset($cat_map[$parent]))
				{
					// Perhaps it was supposed to be their id_cat?
					foreach ($dummy as $board)
					{
						if (empty($cat_map[$board]))
							$cat_map[$board] = $parent;
					}

					$child_map[0] = array_merge(isset($child_map[0]) ? $child_map[0] : array(), $dummy);
					unset($child_map[$parent]);
				}
			}

			// The above id_parents and id_cats may all be wrong; we know id_parent = 0 is right.
			$solid_parents = array(array(0, 0));
			$fixed_boards = array();
			while (!empty($solid_parents))
			{
				list ($parent, $level) = array_pop($solid_parents);
				if (!isset($child_map[$parent]))
					continue;

				// Fix all of this board's children.
				foreach ($child_map[$parent] as $board)
				{
					if ($parent != 0)
						$cat_map[$board] = $cat_map[$parent];
					$fixed_boards[$board] = array($parent, $cat_map[$board], $level);
					$solid_parents[] = array($board, $level + 1);
				}
			}

			foreach ($fixed_boards as $board => $fix)
			{
				$db->query("
					UPDATE {$to_prefix}boards
					SET id_parent = " . (int) $fix[0] . ", id_cat = " . (int) $fix[1] . ", child_level = " . (int) $fix[2] . "
					WHERE id_board = " . (int) $board . "
					LIMIT 1");
			}

			// Leftovers should be brought to the root. They had weird parents we couldn't find.
			if (count($fixed_boards) < count($cat_map))
			{
				$db->query("
					UPDATE {$to_prefix}boards
					SET child_level = 0, id_parent = 0" . (empty($fixed_boards) ? '' : "
					WHERE id_board NOT IN (" . implode(', ', array_keys($fixed_boards)) . ")"));
			}

			// Last check: any boards not in a good category?
			$request = $db->query("
				SELECT id_cat
				FROM {$to_prefix}categories");
			$real_cats = array();
			while ($row = $db->fetch_assoc($request))
				$real_cats[] = $row['id_cat'];
			$db->free_result($request);

			$fix_cats = array();
			foreach ($cat_map as $board => $cat)
			{
				if (!in_array($cat, $real_cats))
					$fix_cats[] = $cat;
			}

			if (!empty($fix_cats))
			{
				$db->query("
					INSERT INTO {$to_prefix}categories
						(name)
					VALUES ('General Category')");
				$catch_cat = mysql_insert_id();

				$db->query("
					UPDATE {$to_prefix}boards
					SET id_cat = " . (int) $catch_cat . "
					WHERE id_cat IN (" . implode(', ', array_unique($fix_cats)) . ")");
			}

			helper::pastTime(9);
		}

		if ($_GET['substep'] <= 9)
		{
			$request = $db->query("
				SELECT c.id_cat, c.cat_order, b.id_board, b.board_order
				FROM {$to_prefix}categories AS c
					LEFT JOIN {$to_prefix}boards AS b ON (b.id_cat = c.id_cat)
				ORDER BY c.cat_order, b.child_level, b.board_order, b.id_board");
			$cat_order = -1;
			$board_order = -1;
			$curCat = -1;
			while ($row = $db->fetch_assoc($request))
			{
				if ($curCat != $row['id_cat'])
				{
					$curCat = $row['id_cat'];
					if (++$cat_order != $row['cat_order'])
						$db->query("
							UPDATE {$to_prefix}categories
							SET cat_order = $cat_order
							WHERE id_cat = $row[id_cat]
							LIMIT 1");
				}
				if (!empty($row['id_board']) && ++$board_order != $row['board_order'])
					$db->query("
						UPDATE {$to_prefix}boards
						SET board_order = $board_order
						WHERE id_board = $row[id_board]
						LIMIT 1");
			}
			$db->free_result($request);

			helper::pastTime(10);
		}

		if ($_GET['substep'] <= 10)
		{
			$db->query("
				ALTER TABLE {$to_prefix}boards
				ORDER BY board_order");

			$db->query("
				ALTER TABLE {$to_prefix}smileys
				ORDER BY code DESC");

			helper::pastTime(11);
		}

		if ($_GET['substep'] <= 11)
		{
			$request = $db->query("
				SELECT COUNT(*)
				FROM {$to_prefix}attachments");
			list ($attachments) = $db->fetch_row($request);
			$db->free_result($request);

			while ($_REQUEST['start'] < $attachments)
			{
				$request = $db->query("
					SELECT id_attach, filename, attachment_type
					FROM {$to_prefix}attachments
					WHERE id_thumb = 0
						AND (RIGHT(filename, 4) IN ('.gif', '.jpg', '.png', '.bmp') OR RIGHT(filename, 5) = '.jpeg')
						AND width = 0
						AND height = 0
					LIMIT $_REQUEST[start], 500");
				if ($db->num_rows($request) == 0)
					break;
				while ($row = $db->fetch_assoc($request))
				{
					if ($row['attachment_type'] == 1)
					{
						$request2 = $db->query("
							SELECT value
							FROM {$to_prefix}settings
							WHERE variable = 'custom_avatar_dir'
							LIMIT 1");
						list ($custom_avatar_dir) = $db->fetch_row($request2);
						$db->free_result($request2);

						$filename = $custom_avatar_dir . '/' . $row['filename'];
					}
					else
						$filename = getLegacyAttachmentFilename($row['filename'], $row['id_attach']);

					// Probably not one of the imported ones, then?
					if (!file_exists($filename))
						continue;

					$size = @getimagesize($filename);
					$filesize = @filesize($filename);
					if (!empty($size) && !empty($size[0]) && !empty($size[1]) && !empty($filesize))
						$db->query("
							UPDATE {$to_prefix}attachments
							SET
								size = " . (int) $filesize . ",
								width = " . (int) $size[0] . ",
								height = " . (int) $size[1] . "
							WHERE id_attach = $row[id_attach]
							LIMIT 1");
				}
				$db->free_result($request);

				// More?
				// We can't keep importing the same files over and over again!
				$_REQUEST['start'] += 500;
				helper::pastTime(11);
			}

			$_REQUEST['start'] = 0;
			helper::pastTime(12);
		}

		// Lets rebuild the indexes.
		if ($_GET['substep'] <= 12)
		{
			$knownKeys = array(
				'PRIMARY' => 'ADD PRIMARY KEY (id_topic)',
				'last_message' => 'ADD UNIQUE last_message (id_last_msg, id_board)',
				'first_message' => 'ADD UNIQUE first_message (id_first_msg, id_board)',
				'poll' => 'ADD UNIQUE poll (ID_POLL, id_topic)',
				'is_sticky' => 'ADD KEY is_sticky (isSticky)',
				'id_board' => 'ADD KEY id_board (id_board)',
				'member_started' => 'ADD KEY member_started (id_member_started, id_board)',
				'last_message_sticky' => 'ADD KEY last_message_sticky (id_board, is_sticky, id_last_msg)',
				'board_news' => 'ADD KEY board_news (id_board, id_first_msg)',
			);
			$db->alter_table('topics', $knownKeys, '', '', true);

			$_REQUEST['start'] = 0;
			helper::pastTime(13);
		}

		if ($_GET['substep'] <= 13)
		{
			$knownKeys = array(
				'PRIMARY' => 'ADD PRIMARY KEY (id_msg)',
				'topic' => 'ADD UNIQUE topic (id_topic, id_msg)',
				'id_board' => 'ADD UNIQUE id_board (id_board, id_msg)',
				'id_member' => 'ADD UNIQUE id_member (id_member, id_msg)',
				'ip_index' => 'ADD KEY ip_index (poster_ip(15), id_topic)',
				'participation' => 'ADD KEY participation (id_member, id_topic)',
				'show_posts' => 'ADD KEY show_posts (id_member, id_board)',
				'id_topic' => 'ADD KEY id_topic (id_topic)',
				'id_member_msg' => 'ADD KEY id_member_msg (id_member, approved, id_msg)',
				'current_topic' => 'ADD KEY current_topic (id_topic, id_msg, id_member, approved)',
			);
			$db->alter_table('messages', $knownKeys, '', '', true);

			$_REQUEST['start'] = 0;
			helper::pastTime(14);
		}

		$template->status(14, 1, false, true);

		return $this->doStep3();
	}

	public function doStep3()
	{
		global $db, $template, $boardurl;

		$to_prefix = $this->to_prefix;

		// add some importer information.
		$db->query("
			REPLACE INTO {$to_prefix}settings (variable, value)
				VALUES ('import_time', " . time() . "),
					('imported_from', '" . $_SESSION['import_script'] . "')");

		$writable = (is_writable(dirname(__FILE__)) && is_writable(__FILE__));
		$template->step3($this->xml->general->name, $boardurl, $writable);

		unset ($_SESSION['import_steps']);

		return true;
	}

}

abstract class helper
{
	/**
	* Checks if we've passed a time limit..
	*
	* @param int $substep
	* @param int $top_time
	* @return null
	*/
	public static function pastTime($substep = null, $stop_time = 5)
	{
		global $template, $import, $time_start, $do_steps;

		if (isset($_GET['substep']) && $_GET['substep'] < $substep)
			$_GET['substep'] = $substep;

		// some details for our progress bar
		if (isset($import->count->$substep) && $import->count->$substep > 0 && isset($_REQUEST['start']) && $_REQUEST['start'] > 0 && isset($substep))
			$bar = round($_REQUEST['start'] / $import->count->$substep * 100, 0);
		else
			$bar = false;

		@set_time_limit(300);
		if (is_callable('apache_reset_timeout'))
			apache_reset_timeout();

		if (time() - $time_start < $stop_time)
			return;

		$template->time_limit($bar);
		$template->footer();
		exit;
	}

	/**
	* helper function for old attachments
	*
	* @param string $filename
	* @param int $attachment_id
	* @return string
	*/
	public static function getLegacyAttachmentFilename($filename, $attachment_id)
	{
		// Remove special accented characters - ie. sí (because they won't write to the filesystem well.)
		$clean_name = strtr($filename, 'ŠŽšžŸÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÑÒÓÔÕÖØÙÚÛÜÝàáâãäåçèéêëìíîïñòóôõöøùúûüýÿ', 'SZszYAAAAAACEEEEIIIINOOOOOOUUUUYaaaaaaceeeeiiiinoooooouuuuyy');
		$clean_name = strtr($clean_name, array('Þ' => 'TH', 'þ' => 'th', 'Ð' => 'DH', 'ð' => 'dh', 'ß' => 'ss', 'Œ' => 'OE', 'œ' => 'oe', 'Æ' => 'AE', 'æ' => 'ae', 'µ' => 'u'));

		// Get rid of dots, spaces, and other weird characters.
		$clean_name = preg_replace(array('/\s/', '/[^\w_\.\-]/'), array('_', ''), $clean_name);

		return $attachment_id . '_' . strtr($clean_name, '.', '_') . md5($clean_name);
	}

	/**
	* // Add slashes recursively...
	*
	* @param array $var
	* @return array
	*/
	public static function addslashes_recursive($var)
	{
		if (!is_array($var))
			return addslashes($var);
		else
		{
			foreach ($var as $k => $v)
				$var[$k] = self::addslashes_recursive($v);
			return $var;
		}
	}

	/**
	* // Remove slashes recursively...
	*
	* @param array $var
	* @return array
	*/
	public static function stripslashes_recursive($var, $level = 0)
	{
		if (!is_array($var))
			return stripslashes($var);

		// Reindex the array without slashes, this time.
		$new_var = array();

		// Strip the slashes from every element.
		foreach ($var as $k => $v)
			$new_var[stripslashes($k)] = $level > 25 ? null : self::stripslashes_recursive($v, $level + 1);

		return $new_var;
	}

	public static function copy_smileys($source, $dest)
	{
		if (!is_dir($source) || !($dir = opendir($source)))
			return;

		while ($file = readdir($dir))
		{
			if ($file == '.' || $file == '..')
				continue;

			// If we have a directory create it on the destination and copy contents into it!
			if (is_dir($source . '/' . $file))
			{
				if (!is_dir($dest))
					@mkdir($dest . '/' . $file, 0777);
				self::copy_dir($source . '/' . $file, $dest . '/' . $file);
			}
			else
			{
				if (!is_dir($dest))
					@mkdir($dest . '/' . $file, 0777);
				copy($source . '/' . $file, $dest . '/' . $file);
			}
		}
		closedir($dir);
	}

	private static function copy_dir($source, $dest)
	{
		if (!is_dir($source) || !($dir = opendir($source)))
			return;

		while ($file = readdir($dir))
		{
			if ($file == '.' || $file == '..')
				continue;

			// If we have a directory create it on the destination and copy contents into it!
			if (is_dir($source . '/'. $file))
			{
				if (!is_dir($dest))
					@mkdir($dest, 0777);
				copy_dir($source . '/' . $file, $dest . '/' . $file);
			}
			else
			{
				if (!is_dir($dest))
					@mkdir($dest, 0777);
				copy($source . '/' . $file, $dest . '/' . $file);
			}
		}
		closedir($dir);
	}

	//Get the id_member associated with the specified message.
	public static function getMsgMemberID($messageID)
	{
		global $to_prefix, $db;

		// Find the topic and make sure the member still exists.
		$result = $db->query("
			SELECT IFNULL(mem.id_member, 0)
			FROM {$to_prefix}messages AS m
				LEFT JOIN {$to_prefix}members AS mem ON (mem.id_member = m.id_member)
			WHERE m.id_msg = " . (int) $messageID . "
			LIMIT 1");
		if ($db->num_rows($result) > 0)
			list ($memberID) = $db->fetch_row($result);
		// The message doesn't even exist.
		else
			$memberID = 0;
		$db->free_result($result);

		return $memberID;
	}
}

class Database
{
	public function __construct($db_server, $db_user, $db_password, $db_persist)
	{
		if ($db_persist == 1)
			$this->con = mysql_pconnect ($db_server, $db_user, $db_password) or die (mysql_error());
		else
			$this->con = mysql_connect ($db_server, $db_user, $db_password) or die (mysql_error());
	}

	private function removeAttachments()
	{
		global $to_prefix;

		$result = $this->query("
			SELECT value
			FROM {$to_prefix}settings
			WHERE variable = 'attachmentUploadDir'
			LIMIT 1");
		list ($attachmentUploadDir) = $this->fetch_row($result);
		$this->free_result($result);

		// !!! This should probably be done in chunks too.
		$result = $this->query("
			SELECT id_attach, filename
			FROM {$to_prefix}attachments");
		while ($row = $this->fetch_assoc($result))
		{
			// We're duplicating this from below because it's slightly different for getting current ones.
			$clean_name = strtr($row['filename'], 'ŠŽšžŸÀÁÂÃÄÅÇÈÉÊËÌÍÎÏÑÒÓÔÕÖØÙÚÛÜÝàáâãäåçèéêëìíîïñòóôõöøùúûüýÿ', 'SZszYAAAAAACEEEEIIIINOOOOOOUUUUYaaaaaaceeeeiiiinoooooouuuuyy');
			$clean_name = strtr($clean_name, array('Þ' => 'TH', 'þ' => 'th', 'Ð' => 'DH', 'ð' => 'dh', 'ß' => 'ss', 'Œ' => 'OE', 'œ' => 'oe', 'Æ' => 'AE', 'æ' => 'ae', 'µ' => 'u'));
			$clean_name = preg_replace(array('/\s/', '/[^\w_\.\-]/'), array('_', ''), $clean_name);
			$enc_name = $row['id_attach'] . '_' . strtr($clean_name, '.', '_') . md5($clean_name);
			$clean_name = preg_replace('~\.[\.]+~', '.', $clean_name);

			if (file_exists($attachmentUploadDir . '/' . $enc_name))
				$filename = $attachmentUploadDir . '/' . $enc_name;
			else
				$filename = $attachmentUploadDir . '/' . $clean_name;

			@unlink($filename);
		}
		$this->free_result($result);
	}

	public function query($string, $return_error = false)
	{
		global $template, $to_prefix;

		// Debugging?
		if (isset($_REQUEST['debug']))
			$_SESSION['import_debug'] = !empty($_REQUEST['debug']);

		if (trim($string) == 'TRUNCATE ' . $GLOBALS['to_prefix'] . 'attachments')
			$this->removeAttachments();

		$result = @mysql_query($string);

		if ($result !== false || $return_error)
			return $result;

		$mysql_error = mysql_error();
		$mysql_errno = mysql_errno();

		if ($mysql_errno == 1016)
		{
			if (preg_match('~(?:\'([^\.\']+)~', $mysql_error, $match) != 0 && !empty($match[1]))
				mysql_query("
					REPAIR TABLE $match[1]");

			$result = mysql_query($string);

			if ($result !== false)
				return $result;
		}
		elseif ($mysql_errno == 2013)
		{
			$result = mysql_query($string);

			if ($result !== false)
				return $result;
		}

		// Get the query string so we pass everything.
		if (isset($_REQUEST['start']))
			$_GET['start'] = $_REQUEST['start'];
		$query_string = '';
		foreach ($_GET as $k => $v)
			$query_string .= '&' . $k . '=' . $v;
		if (strlen($query_string) != 0)
			$query_string = '?' . strtr(substr($query_string, 1), array('&' => '&amp;'));

		echo '
				<b>Unsuccessful!</b><br />
				This query:<blockquote>' . nl2br(htmlspecialchars(trim($string))) . ';</blockquote>
				Caused the error:<br />
				<blockquote>' . nl2br(htmlspecialchars($mysql_error)) . '</blockquote>
				<form action="', $_SERVER['PHP_SELF'], $query_string, '" method="post">
					<input type="submit" value="Try again" />
				</form>
			</div>';

		$template->footer();
		die;
	}

	public function free_result($result)
	{
		mysql_free_result($result);
	}

	public function fetch_assoc($result)
	{
		return mysql_fetch_assoc($result);
	}

	public function fetch_row($result)
	{
		return mysql_fetch_row($result);
	}

	public function num_rows($result)
	{
		return mysql_num_rows($result);
	}
	public function insert_id()
	{
		return mysql_insert_id();
	}

	public function alter_table($tableName, $knownKeys = '', $knownColumns = '', $alterColumns = '', $reverseKeys = false, $reverseColumns = false, $return_error = false)
	{
		global $to_prefix, $db;

		// Shorten this up
		$to_table = $to_prefix . $tableName;

		// Get the keys
		if (!empty($knownKeys))
		{
			$request = $db->query("
				SHOW KEYS
				FROM $to_table");

			$availableKeys = array();
			while ($row = $db->fetch_assoc($request))
				$availableKeys[] = $row['Key_name'];

			// Flip the keys.
			array_flip($availableKeys);
		}
		else
			$knownKeys = array();

		// Are we dealing with columns also?
		if (!empty($knownColumns))
		{
			$request = $db->query("
				SHOW COLUMNS
				FROM $to_table");

			$availableColumns = array();
			while ($row = $db->fetch_assoc($request))
				$availableColumns[] = $row['Field'];

			array_flip($availableColumns);
		}
		else
			$knownColumns = array();

		// Column to alter
		if (!empty($alterColumns) && is_array($alterColumns))
			$alterColumns = $alterColumns;
		else
			$alterColumns = array();

		// Check indexes
		foreach ($knownKeys as $key => $value)
		{
			// If we are dropping keys then it should unset the known keys if it's NOT available
			if ($reverseKeys == false && !in_array($key, $availableKeys))
				unset($knownKeys[$key], $knownKeys[$key]);
			// Since we are in reverse and we are adding then unknown the known keys that are available
			elseif ($reverseKeys == true && in_array($key, $availableKeys))
				unset($knownKeys[$key], $knownKeys[$key]);
		}

		// Check columns
		foreach ($knownColumns as $column => $value)
		{
			// Here we reverse things. If the column is not in then we must add it.
			if ($reverseColumns == false && in_array($column, $availableColumns))
				unset($knownColumns[$column], $knownColumns[$column]);
			// If it's in then we must unset it.
			elseif ($reverseColumns == true && !in_array($column, $availableColumns))
				unset($knownColumns[$column], $knownColumns[$column]);
		}

		// Now merge the three
		$alter = array_merge($alterColumns, $knownKeys, $knownColumns);

		// Now lets see what we want to do with them
		$clause = '';
		foreach ($alter as $key)
			$clause .= "
			$key,";

		// Lets do some altering
		$db->query("
			ALTER TABLE $to_table" .
			substr($clause, 0, -1), $return_error);
	}
}

/*
* 	class Charset(string data)
*		- this is our main class for proper character encoding
* 		- whatever we throw in, the output will be clean
*
*	array Charset::fix (string data or array)
*		- this function can convert an array recursively to utf-8
*		- The input can have mixed encodings.
*
*	bool Charset::is_utf8(string data)
*		- returns whether the string is already utf8 or not
*/
class Charset
{
	// simple function to detect whether a string is utf-8 or not
	private static function is_utf8($string)
	{
		return utf8_encode(utf8_decode($string)) == $string;
	}

	/**
	* Function fix based on ForceUTF8 by Sebastián Grignoli <grignoli@framework2.com.ar>
	* @link http://www.framework2.com.ar/dzone/forceUTF8-es/
	* This function leaves UTF8 characters alone, while converting almost all non-UTF8 to UTF8.
	*
	* It may fail to convert characters to unicode if they fall into one of these scenarios:
	*
	* 1) when any of these characters:   ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß
	*    are followed by any of these:  ("group B")
	*                                    ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶•¸¹º»¼½¾¿
	* For example:   %ABREPR%C9SENT%C9%BB. «REPRÉSENTÉ»
	* The "«" (%AB) character will be converted, but the "É" followed by "»" (%C9%BB)
	* is also a valid unicode character, and will be left unchanged.
	*
	* 2) when any of these: àáâãäåæçèéêëìíîï  are followed by TWO chars from group B,
	* 3) when any of these: ðñòó  are followed by THREE chars from group B.
	*
	* @name fix
	* @param string $text  Any string.
	* @return string  The same string, UTF8 encoded
	*/
	public static function fix($text)
	{
		if (is_array($text))
		{
			foreach ($text as $k => $v)
				$text[$k] = self::fix($v);
			return $text;
		}

		// numeric? There's nothing to do, we simply return our input.
		if (is_numeric($text))
			return $text;

		$max = strlen($text);
		$buf = '';

		for ($i = 0; $i < $max; $i++)
		{
			$c1 = $text{$i};
			if ($c1 >= "\xc0")
			{
				//Should be converted to UTF8, if it's not UTF8 already
				$c2 = $i+1 >= $max? "\x00" : $text{$i+1};
				$c3 = $i+2 >= $max? "\x00" : $text{$i+2};
				$c4 = $i+3 >= $max? "\x00" : $text{$i+3};
				if ($c1 >= "\xc0" & $c1 <= "\xdf")
				{
					// looks like 2 bytes UTF8
					if ($c2 >= "\x80" && $c2 <= "\xbf")
					{
						// yeah, almost sure it's UTF8 already
						$buf .= $c1 . $c2;
						$i++;
					}
					else
					{
						// not valid UTF8. Convert it.
						$cc1 = (chr(ord($c1) / 64) | "\xc0");
						$cc2 = ($c1 & "\x3f") | "\x80";
						$buf .= $cc1 . $cc2;
					}
				}
				elseif ($c1 >= "\xe0" & $c1 <= "\xef")
				{
					// looks like 3 bytes UTF8
					if ($c2 >= "\x80" && $c2 <= "\xbf" && $c3 >= "\x80" && $c3 <= "\xbf")
					{
						// yeah, almost sure it's UTF8 already
						$buf .= $c1 . $c2 . $c3;
						$i = $i + 2;
					}
					else
					{
						// not valid UTF8. Convert it.
						$cc1 = (chr(ord($c1) / 64) | "\xc0");
						$cc2 = ($c1 & "\x3f") | "\x80";
						$buf .= $cc1 . $cc2;
					}
				}
				elseif ($c1 >= "\xf0" & $c1 <= "\xf7")
				{
					// Looks like 4-byte UTF8
					if ($c2 >= "\x80" && $c2 <= "\xbf" && $c3 >= "\x80" && $c3 <= "\xbf" && $c4 >= "\x80" && $c4 <= "\xbf")
					{
						// Yeah, almost sure it's UTF8 already
						$buf .= $c1 . $c2 . $c3;
						$i = $i + 2;
					}
					else
					{
						// Not valid UTF8. Convert it.
						$cc1 = (chr(ord($c1) / 64) | "\xc0");
						$cc2 = ($c1 & "\x3f") | "\x80";
						$buf .= $cc1 . $cc2;
					}
				}
				else
				{
					// Doesn't look like UTF8, but should be converted
					$cc1 = (chr(ord($c1) / 64) | "\xc0");
					$cc2 = (($c1 & "\x3f") | "\x80");
					$buf .= $cc1 . $cc2;
				}
			}
			elseif (($c1 & "\xc0") == "\x80")
			{
				// Needs conversion
				$cc1 = (chr(ord($c1) / 64) | "\xc0");
				$cc2 = (($c1 & "\x3f") | "\x80");
				$buf .= $cc1 . $cc2;
			}
			else
				// Doesn't need conversion
				$buf .= $c1;
		}

		if (function_exists('mb_decode_numericentity'))
			$buf = mb_decode_numericentity($buf, array(0x80, 0x2ffff, 0, 0xffff), 'UTF-8');
		else
		{
			// Take care of html entities..
			$entity_replace = create_function('$num', '
				return $num < 0x20 || $num > 0x10FFFF || ($num >= 0xD800 && $num <= 0xDFFF) ? \'\' :
					  ($num < 0x80 ? \'&#\' . $num . \';\' : ($num < 0x800 ? chr(192 | $num >> 6) . chr(128 | $num & 63) :
					  ($num < 0x10000 ? chr(224 | $num >> 12) . chr(128 | $num >> 6 & 63) . chr(128 | $num & 63) :
					  chr(240 | $num >> 18) . chr(128 | $num >> 12 & 63) . chr(128 | $num >> 6 & 63) . chr(128 | $num & 63))));');

			$buf = preg_replace('~(&#(\d{1,7}|x[0-9a-fA-F]{1,6});)~e', '$entity_replace(\\2)', $buf);
			$buf = preg_replace('~(&#x(\d{1,7}|x[0-9a-fA-F]{1,6});)~e', '$entity_replace(0x\\2)', $buf);
		}

		// surprise, surprise... the string
		return $buf;
	}
}

	/**
	* Object lng provides storage for shared objects
	*
	* @var array $lang
	*/
class lng
{
	private static $lang = array();

	/**
	* Adds a new variable to the lang.
	*
	* @param string $key Name of the variable
	* @param mixed $value Value of the variable
	* @throws Exception
	* @return bool
	*/
	protected static function set($key, $value)
	{
		try
		{
				if (!self::has($key))
				{
					self::$lang[$key] = $value;
					return true;
				}
				else
					throw new Exception('Unable to set language string for  <em>' . $key . '</em>. It was already set.');
		}
		catch(Exception $e)
		{
			import_exception::exception_handler($e);
		}
	}

	/**
	* load the language xml in lang
	*
	* @return null
	*/
	public static function loadLang()
	{
		// detect the browser language
		$language = self::detect_browser_language();

		// loop through the prefered languages and try to find the related language file
		foreach ($language as $key => $value)
		{
			if (file_exists(dirname(__FILE__) . '/import_' . $key . '.xml'))
			{
				$lngfile = dirname(__FILE__) . '/import_' . $key . '.xml';
				break;
			}
		}
		// english is still better than nothing
		if (!isset($lngfile))
		{
			if (file_exists(dirname(__FILE__) . '/import_en.xml'))
				$lngfile = dirname(__FILE__) . '/import_en.xml';
		}
		// ouch, we really should never arrive here..
		if (!$lngfile)
			throw new Exception('Unable to detect language file!');

		$langObj = simplexml_load_file($lngfile, 'SimpleXMLElement', LIBXML_NOCDATA);

		foreach ($langObj as $strings)
			self::set((string) $strings->attributes()->{'name'}, (string) $strings);

		return null;
	}
	/**
	* Tests if given $key exists in lang
	*
	* @param string $key
	* @return bool
	*/
	public static function has($key)
	{
		if (isset(self::$lang[$key]))
			return true;

		return false;
	}

	/**
	* Returns the value of the specified $key in lang.
	*
	* @param string $key Name of the variable
	* @return mixed Value of the specified $key
	*/
	public static function get($key)
	{
		if (self::has($key))
			return self::$lang[$key];

		return null;
	}
	/**
	* Returns the whole lang as an array.
	*
	* @return array Whole lang
	*/
	public static function getAll()
	{
		return self::$lang;
	}

	protected static function detect_browser_language()
	{

		if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE']))
		{
			// break up string into pieces (languages and q factors)
			preg_match_all('/([a-z]{1,8}(-[a-z]{1,8})?)\s*(;\s*q\s*=\s*(1|0\.[0-9]+))?/i', strtolower($_SERVER['HTTP_ACCEPT_LANGUAGE']), $lang_parse);

			if (count($lang_parse[1]))
			{
				// create a list like "en" => 0.8
				$prefered = array_combine($lang_parse[1], $lang_parse[4]);

				// set default to 1 for any without q factor (IE fix)
				foreach ($prefered as $lang => $val)
				{
					if ($val === '')
						$prefered[$lang] = 1;
				}

				// sort list based on value
				arsort($prefered, SORT_NUMERIC);
			}
		}
		return $prefered;
	}

}

	/**
	* this is our UI
	*
	*/
class template
{
	/**
	* Display a specific error message.
	*
	* @param string $error_message
	* @param int $trace
	* @param int $line
	* @param string $file
	*/
	public function error($error_message, $trace = false, $line = false, $file = false)
	{
		echo '
			<div class="error_message">
				<div class="error_text">', isset($trace) && !empty($trace) ? 'Message: ' : '', is_array($error_message) ? sprintf($error_message[0], $error_message[1]) : $error_message , '</div>';
		if (isset($trace) && !empty($trace))
			echo '<div class="error_text">Trace: ', $trace , '</div>';
		if (isset($line) && !empty($line))
			echo '<div class="error_text">Line: ', $line , '</div>';
		if (isset($file) && !empty($file))
			echo '<div class="error_text">File: ', $file , '</div>';
		echo '
			</div>';
	}

	/**
	* Show the footer.
	*
	* @param bol $inner
	*/
	public function footer($inner = true)
	{
		if (!empty($_GET['step']) && ($_GET['step'] == 1 || $_GET['step'] == 2) && $inner == true)
			echo '
				</p>
			</div>';
		echo '
		</div>
	</body>
</html>';
	}
	/**
	* Show the header.
	*
	* @param bol $inner
	*/
	public function header($inner = true)
	{
		global $import, $time_start;
		$time_start = time();

		echo '<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="', lng::get('we.imp.locale'), '" lang="', lng::get('we.imp.locale'), '">
	<head>
		<meta charset="UTF-8" />
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<title>', isset($import->xml->general->name) ? $import->xml->general->name . ' to ' : '', 'Wedge Importer</title>
		<script type="text/javascript">
			function AJAXCall(url, callback, string) {
				var req = init();
				var string = string;
				req.onreadystatechange = processRequest;

				function init() {
					if (window.XMLHttpRequest) {
						return new XMLHttpRequest();
					} else if (window.ActiveXObject) {
						return new ActiveXObject("Microsoft.XMLHTTP");
					}
				}

				function processRequest () {
				// readyState of 4 signifies request is complete
				if (req.readyState == 4) {
					// status of 200 signifies sucessful HTTP call
					if (req.status == 200) {
						if (callback) callback(req.responseXML, string);
					}
				}
			}

				this.doGet = function() {
					// make a HTTP GET request to the URL asynchronously
					req.open("GET", url, true);
					req.send(null);
				}
			}

			function validateField(string) {
				var target = document.getElementById(string);
				var from = "', isset($import->xml->general->settings) ? $import->xml->general->settings : 'null', '";
				var to = "/Settings.php";

				if (string == "path_to")
					extend = to;
				else
					extend = from;

				var url = "import.php?xml=true&"+ string + "=" + target.value + extend;
				var ajax = new AJAXCall(url, validateCallback, string);
				ajax.doGet();
			}

			function validateCallback(responseXML, string) {
				var msg = responseXML.
				getElementsByTagName("valid")[0].firstChild.nodeValue;
				if (msg == "false") {
					var field = document.getElementById(string);
					var validate = document.getElementById(\'validate_\' + string);
					field.className = "invalid_field";
					validate.innerHTML = "invalid path, installation not found!";
					// set the style on the div to invalid
					var submitBtn = document.getElementById("submit_button");
					submitBtn.disabled = true;
				}
				else {
					var field = document.getElementById(string);
					var validate = document.getElementById(\'validate_\' + string);
					field.className = "valid_field";
					validate.innerHTML = "installation validated!";
					var submitBtn = document.getElementById("submit_button");
					submitBtn.disabled = false;
				}
			}
		</script>
		<style type="text/css">
			body
			{
				background-color: #FFFDFA;
				margin: 0px;
				padding: 0px;
			}
			body, td
			{
				color: #000;
				font-size: small;
				font-family: arial;
			}
			a
			{
				color: #660000;
				text-decoration: none;
				border-bottom: 1px dashed #660000;
			}
			#header
			{
				background-color: #8B7E7E;
				padding: 22px 4% 12px 4%;
				color: #FFF5C2;
				font-size: xx-large;
				border-bottom: 3px solid #FD9604;
				height: 40px;
			}
			#main
			{
				padding: 20px 30px;
			}
			.error_message, blockquote, .error
			{
				border: 1px dashed red;
				border-radius: 5px;
				background-color: #fee;
				margin: 1ex 4ex;
				padding: 1.5ex;
			}
			.error_text
			{
				color: red;
			}
			.content
			{
				border-radius: 6px;
				background-color: #EDEFE6;
				color: #444;
				margin: 1ex 0;
				padding: 1.2ex;
			}
			h1
			{
				margin: 0;
				padding: 0;
				font-size: 24pt;
			}
			h2
			{
				margin: 0 0 0 0;
				position: relative;
				top: 15px;
				border-radius: 7px;
				left: 10px;
				padding: 5px;
				display: inline;
				background-color: #fff;
				font-size: 10pt;
				color: #866;
				font-weight: bold;
			}
			form
			{
				margin: 0;
			}
			.textbox
			{
				padding-top: 2px;
				white-space: nowrap;
				padding-right: 1ex;
			}
			.bp_invalid
			{
				color:red;
				font-weight: bold;
			}
			.bp_valid
			{
				color:green;
			}
			.validate
			{
				font-style: italic;
				font-size: smaller;
			}
			.valid_field
			{
				background-color: #DEFEDD;
				border: 1px solid green;
			}
			.invalid_field
			{
				background-color: #fee;;
				border: 1px solid red;
			}
			#progressbar
			{
				position: relative;
				top: -28px;
				left: 255px;
				width: 300px;
				height: 0.7em;
				background-color: white;
				border-radius: 4px;
				border: 1px solid #ddd;
			}
			#inner_bar
			{
				background-color: orange;
				height: 0.7em;
				border-bottom-left-radius: 4px;
				border-top-left-radius: 4px;
			}
			dl
			{
				clear: right;
				overflow: auto;
				margin: 0 0 0 0;
				padding: 0;
			}
			dt
			{
				width: 15%;
				float: left;
				margin: 6px 5px 10px 0;
				padding: 0;
				clear: both;
			}
			dd
			{
				width: 82%;
				float: right;
				margin: 6px 0 3px 0;
				padding: 0;
			}
			#arrow_up
			{
				display: none;
			}
			#toggle_button
			{
				display: block;
				color: #600;
				margin-bottom: 4px;
				cursor: pointer;
			}
			.arrow
			{
				font-size: 8pt;
			}
		</style>
	</head>
	<body>
		<div id="header">
			<h1 title="SMF is dead. Wedge is your future :-P">', isset($import->xml->general->{'name'}) ? $import->xml->general->{'name'} . ' to ' : '', 'Wedge Importer</h1>
		</div>
		<div id="main">';

		if (!empty($_GET['step']) && ($_GET['step'] == 1 || $_GET['step'] == 2) && $inner == true)
			echo '
			<h2 style="margin-top: 2ex">', lng::get('we.imp.importing'), '...</h2>
			<div class="content"><p>';
	}

	public function select_script($scripts)
	{
		echo '
			<h2>', lng::get('we.imp.which_software'), '</h2>
			<div class="content">';

		if (!empty($scripts))
		{
			echo '
				<p>', lng::get('we.imp.multiple_files'), '</p>
				<ul>';

			foreach ($scripts as $script)
				echo '
					<li>
						<a href="', $_SERVER['PHP_SELF'], '?import_script=', $script['path'], '">', $script['name'], '</a>
						<span>(', $script['path'], ')</span>
					</li>';

			echo '
				</ul>
			</div>
			<h2>', lng::get('we.imp.not_here'), '</h2>
			<div class="content">
				<p>', lng::get('we.imp.check_more'), '</p>
				<p>', lng::get('we.imp.having_problems'), '</p>';
		}
		else
		{
			echo '
				<p>', lng::get('we.imp.not_found'), '</p>
				<p>', lng::get('we.imp.not_found_download'), '</p>
				<a href="', $_SERVER['PHP_SELF'], '?import_script=">', lng::get('we.imp.try_again'), '</a>';
		}

		echo '
			</div>';
	}

	public function step0($object, $steps, $test_from, $test_to)
	{
		echo '
			<h2>', lng::get('we.imp.before_continue'), '</h2>
			<div class="content">
				<p>', sprintf(lng::get('we.imp.before_details'), (string) $object->xml->general->name ), '</p>
			</div>';
		echo '
			<h2>', lng::get('we.imp.where'), '</h2>
			<div class="content">
				<form action="', $_SERVER['PHP_SELF'], '?step=1', isset($_REQUEST['debug']) ? '&amp;debug=' . $_REQUEST['debug'] : '', '" method="post">
					<p>', lng::get('we.imp.locate_wedge'), '</p>
					<div id="toggle_button">', lng::get('we.imp.advanced_options'), ' <span id="arrow_down" class="arrow">&#9660</span><span id="arrow_up" class="arrow">&#9650</span></div>
					<dl id="advanced_options" style="display: none; margin-top: 5px">
						<dt><label for="path_to">', lng::get('we.imp.path_to_wedge'), ':</label></dt>
						<dd>
							<input type="text" name="path_to" id="path_to" value="', $_POST['path_to'], '" size="60" onblur="validateField(\'path_to\')" />
							<div id="validate_path_to" class="validate">', $test_to ? lng::get('we.imp.right_path') : lng::get('we.imp.change_path'), '</div>
						</dd>
					</dl>
					<dl>';

		if ($object->xml->general->settings)
			echo '
						<dt><label for="path_from">', lng::get('we.imp.path_to_source'),' ', $object->xml->general->name, ':</label></dt>
						<dd>
							<input type="text" name="path_from" id="path_from" value="', $_POST['path_from'], '" size="60" onblur="validateField(\'path_from\')" />
							<div id="validate_path_from" class="validate">', $test_from ? lng::get('we.imp.right_path') : lng::get('we.imp.change_path'), '</div>
						</dd>';

		//Any custom form elements?
		if ($object->xml->general->form)
		{
			foreach ($object->xml->general->form->children() as $field)
			{
				if ($field->attributes()->{'type'} == 'text')
					echo '
						<dt><label for="field', $field->attributes()->{'id'}, '">', $field->attributes()->{'label'}, ':</label></dt>
						<dd><input type="text" name="field', $field->attributes()->{'id'}, '" id="field', $field->attributes()->{'id'}, '" value="" size="', $field->attributes()->{'size'}, '" /></dd>';

				elseif ($field->attributes()->{'type'}== 'checked' || $field->attributes()->{'type'} == 'checkbox')
					echo '
						<dt></dt>
						<dd>
							<label for="field', $field->attributes()->{'id'}, '">
								<input type="checkbox" name="field', $field->attributes()->{'id'}, '" id="field', $field->attributes()->{'id'}, '" value="1"', $field->attributes()->{'type'} == 'checked' ? ' checked="checked"' : '', ' /> ', $field->attributes()->{'label'}, '
							</label>
						</dd>';
			}
		}

		echo '
						<dt><label for="db_pass">', lng::get('we.imp.database_passwd'),':</label></dt>
						<dd>
							<input type="password" name="db_pass" size="30" class="text" />
							<div style="font-style: italic; font-size: smaller">', lng::get('we.imp.database_verify'),'</div>
						</dd>';


		// Now for the steps.
		if (!empty($steps))
		{
			echo '
						<dt>', lng::get('we.imp.selected_only'),':</dt>
						<dd>';
			foreach ($steps as $key => $step)
				echo '
							<input type="checkbox" name="do_steps[', $key, ']" id="do_steps[', $key, ']" value="', $step['count'], '"', ($step['mandatory'] ? 'readonly="readonly" ': ' '), ' checked="checked" />', ucfirst(str_replace('importing ', '', $step['name'])), '<br />';

			echo '
						</dd>';
		}

		echo '
					</dl>
					<div align="right" style="margin: 1ex; margin-top: 0"><input id="submit_button" name="submit_button" type="submit" value="', lng::get('we.imp.continue'),'" class="submit" /></div>
				</form>
			</div>';

		if (!empty($GLOBALS['possible_scripts']))
			echo '
			<h2>', lng::get('we.imp.not_this'),'</h2>
			<div class="content">
				<p>', sprintf(lng::get('we.imp.pick_different'), $_SERVER['PHP_SELF']), '</p>
			</div>';
		echo '
			<script type="text/javascript">
				document.getElementById(\'toggle_button\').onclick = function() {
					var elem = document.getElementById(\'advanced_options\');
					var arrow_up = document.getElementById(\'arrow_up\');
					var arrow_down = document.getElementById(\'arrow_down\');
					if (!elem)
						return true;

					if (elem.style.display == \'none\')
					{
						elem.style.display = \'block\';
						arrow_down.style.display = \'none\';
						arrow_up.style.display = \'inline\';
					}
					else
					{
						elem.style.display = \'none\';
						arrow_down.style.display = \'inline\';
						arrow_up.style.display = \'none\';
					}

					return true;
				}
			</script>';

	}

	public function status($substep, $status, $title, $hide = false)
	{
		if (isset($title) && $hide == false)
			echo '<span style="width: 250px; display: inline-block">' . $title . '...</span> ';

		if ($status == 1)
			echo '<span style="color: green">&#x2714</span>';

		if ($status == 2)
			echo '<span style="color: grey">&#x2714</span> (', lng::get('we.imp.skipped'),')';

		if ($status == 3)
			echo '<span style="color: red">&#x2718</span> (', lng::get('we.imp.not_found_skipped'),')';

		if ($status != 0)
			echo '<br />';
	}

	public function step2()
	{
		echo '
				<span style="width: 250px; display: inline-block">', lng::get('we.imp.recalculate'), '...</span> ';
	}

	public function step3($name, $boardurl, $writable)
	{
		echo '
			</div>
			<h2 style="margin-top: 2ex">', lng::get('we.imp.complete'), '</h2>
			<div class="content">
			<p>', lng::get('we.imp.congrats'),'</p>';

		if ($writable)
			echo '
				<div style="margin: 1ex; font-weight: bold">
					<label for="delete_self"><input type="checkbox" id="delete_self" onclick="doTheDelete()" />', lng::get('we.imp.check_box'), '</label>
				</div>
				<script type="text/javascript"><!-- // --><![CDATA[
					function doTheDelete()
					{
						var theCheck = document.getElementById ? document.getElementById("delete_self") : document.all.delete_self;
						var tempImage = new Image();
						tempImage.src = "', $_SERVER['PHP_SELF'], '?delete=1&" + (new Date().getTime());
						tempImage.width = 0;
						theCheck.disabled = true;
					}
				// ]]></script>';
		echo '
				<p>', sprintf(lng::get('we.imp.all_imported'), $name), '</p>
				<p>', lng::get('we.imp.smooth_transition'), '</p>';
	}

	public function time_limit($bar)
	{
		if (isset($bar))
			echo '
			<div id="progressbar">
				<div id="inner_bar" style="width:', $bar, '%"></div>
			</div>';

		echo '
		</div>
		<h2 style="margin-top: 2ex">', lng::get('we.imp.not_done'),'</h2>
		<div class="content">
			<p>', lng::get('we.imp.importer_paused'),'</p>';

		echo '
			<form action="', $_SERVER['PHP_SELF'], '?step=', $_GET['step'], isset($_GET['substep']) ? '&amp;substep=' . $_GET['substep'] : '', '&amp;start=', $_REQUEST['start'], '" method="post" name="autoSubmit">
				<div align="right" style="margin: 1ex"><input name="b" type="submit" value="', lng::get('we.imp.continue'),'" /></div>
			</form>';

		echo '
			<script type="text/javascript"><!-- // --><![CDATA[
				var countdown = 3;
				window.onload = doAutoSubmit;

				function doAutoSubmit()
				{
					if (countdown == 0)
						document.autoSubmit.submit();
					else if (countdown == -1)
						return;

					document.autoSubmit.b.value = "', lng::get('we.imp.continue'),' (" + countdown + ")";
					countdown--;

					setTimeout("doAutoSubmit();", 1000);
				}
			// ]]></script>';
	}

	public function xml()
	{
		global $import;

		if (isset($_GET['doStep']) && isset($_GET['bypass']))
		{
			$temp = unserialize($_GET['bypass']);
			foreach ($temp as $key => $value)
				$_SESSION[$key] = $value;

			$json = array(
				'status' => '1',
				'next' => '2'
			);

			return true;
		}

		if (isset($_GET['path_to']))
			$test_to = file_exists($_GET['path_to']);
		elseif (isset($_GET['path_from']))
			$test_to = file_exists($_GET['path_from']);
		else
			$test_to = false;

		header('Content-Type: text/xml');
		echo '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<valid>', $test_to ? 'true' : 'false' ,'</valid>';
	}

	public function ajax_importer()
	{

	echo '
		<div id="ajax_progress"></div>
			<script type="text/javascript">
				// define these variables
				var interval = \'5000\';
				var file = \'import.php?xml=true&doStep=true&bypass=', $bypass, '\';
				var myelement = \'ajax_progress\';
				var json;

				function createRequestObject()
				{
					var req;

					if (window.XMLHttpRequest)
						req = new XMLHttpRequest();

					else if (window.ActiveXObject)
						req = new ActiveXObject("Microsoft.XMLHTTP");

					return req;
				}

				// Make the XMLHttpRequest object
				var http = createRequestObject();

				function sendRequest(page)
				{
					http.open(\'get\', page);
					http.onreadystatechange = handleResponse;
					http.setRequestHeader("Pragma", "no-cache");
					http.setRequestHeader("Cache-Control", "must-revalidate");
					http.setRequestHeader("If-Modified-Since", document.lastModified);
					http.send(null);
				}

				function handleResponse()
				{

					if (http.readyState == 4 && http.status == 200)
					{
						// the PHP output
						var response = http.responseText;
						// json = eval(\'(\'+ http.responseText +\')\');
						if (response)
							document.getElementById(myelement).innerHTML = response;
					}
				}

				function loop()
				{
					sendRequest(file +json);
					setTimeout("loop()", interval);
				}

				window.onload = function()
				{
					loop();
				}
			</script>';
	}
}

/**
* class import_exception extends the build-in Exception class and
* catches potential errors
*/
class import_exception extends Exception
{
	public static function error_handler_callback($code, $string, $file, $line, $context)
	{
		global $import;

		$e = new self($string, $code);
		$e->line = $line;
		$e->file = $file;
		throw $e;
	}

	public static function exception_handler($exception)
	{
		global $template, $import;

		$template = new template();

		$template->header();

		$message = $exception->getMessage();
		$trace = $exception->getTrace();
		$line = $exception->getLine();
		$file = $exception->getFile();
		$template->error($message, $trace[0]['args'][1], $line, $file);

		$template->footer();
	}
}

class Cookie
{
	public function Cookie()
	{
		return true;
	}

	public function set($data, $name = 'wedge_importer_cookie')
	{
		if (!empty($data))
		{
			setcookie($name, serialize($data), time()+ 86400);
			$_COOKIE[$name] = serialize($data);
			return true;
		}
		return false;
	}

	public function get($name = 'wedge_importer_cookie')
	{
		if (isset($_COOKIE[$name]))
		{
			$cookie = unserialize($_COOKIE[$name]);
			return $cookie;
		}

		return false;
	}

	public function destroy($name = 'wedge_importer_cookie')
	{
		setcookie($name, '');
		unset($_COOKIE[$name]);

		return true;
	}

	public function extend($data, $name = 'wedge_importer_cookie')
	{
		$cookie = unserialize($_COOKIE[$name]);
		if (!empty($cookie) && isset($data))
			$merged = array_merge((array)$cookie, (array)$data);

		$this->set($merged);
		$_COOKIE[$name] = serialize($merged);

		return true;
	}
}
?>