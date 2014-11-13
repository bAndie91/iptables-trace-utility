<?php
 
$logfile = "/var/log/iptables.log";
$Response = array();
$GLOBALS['text'] = '';

function iptables($table, $action, $chain, $options = array(), &$stdout = '')
{
	$cmd = "sudo iptables ";
	$cmd .= "-t $table ";
	$cmd .= "-$action ";
	$cmd .= "$chain ";

	foreach($options as $optval)
	{
		$cmd .= "$optval ";
	}

	$cmd .= "2>&1";

	if(@$_REQUEST["debug"])
	{
		$GLOBALS['text'] .= print_r($cmd, true).PHP_EOL;
	}
	exec($cmd, $stdout_array, $code);
	$stdout = implode(PHP_EOL, $stdout_array);
	if(@$_REQUEST["debug"])
	{
		$GLOBALS['text'] .= print_r($stdout, true);
	}
	return $code == 0;
}

function which($cmd)
{
	foreach(explode(':', getenv('PATH')) as $path)
	{
		if(is_executable("$path/$cmd")) return true;
	}
	return false;
}

function run($cmd)
{
	exec("$cmd 2>&1", $stdout_array, $code);
	if($code != 0)
	{
		return $code;
	}
	else
	{
		return implode(PHP_EOL, $stdout_array);
	}
}

function iptables_save()
{
	$cmd = "sudo iptables-save";
	exec($cmd, $stdout, $code);
	if($code == 0)
	{
		return implode(PHP_EOL, $stdout);
	}
	else
	{
		return NULL;
	}
}

function htmlize($raw)
{
	$return = '';
	$cur_table = NULL;
	$rule_number = NULL;
	foreach(explode(PHP_EOL, $raw) as $line)
	{
		$attributes = array();
		$lchr = substr($line, 0, 1);
		$chain_prev = $chain;
		$chain = NULL;
		switch($lchr)
		{
			case '*':
				$cur_table = substr($line, 1);
			break;
			case 'C':
				$cur_table = NULL;
			break;
			case ':':
				$chain = substr($line, 1, strpos($line, ' ')-1);
			break;
			case '-':
				$chain = substr($line, 3, strpos($line, ' ', 3)-3);
				if($chain_prev == $chain)
				{
					$rule_number++;
				}
				else
				{
					$rule_number = 1;
				}
			break;
		}
		if($lchr != '-')
		{
			$rule_number = NULL;
		}
		if(isset($cur_table)) $attributes[] = "table=\"$cur_table\"";
		if(isset($chain)) $attributes[] = "chain=\"$chain\"";
		if(isset($rule_number)) $attributes[] = "rule=\"$rule_number\"";
		$return .= "<span ".implode(' ', $attributes).">".htmlentities($line)."</span><br/>";
	}
	return $return;
}


switch($_REQUEST['act'])
{
	case "setup":
		session_start();
		$_SESSION["pos"] = filesize($logfile);

		$trace_options = array();
		$trace_chains = array();
		
		foreach($_REQUEST['filters'] as $rule_num => $rule)
		{
			$trace_options[$rule_num] = array();
			
			if(empty($rule['option']['limit']))
			{
				$rule['option']['limit'] = 1;
			}
			if(empty($rule['option']['limit_per']))
			{
				$rule['option']['limit_per'] = "sec";
			}
			$rule['option']['limit'] .= "/" . $rule['option']['limit_per'];
			unset($rule['option']['limit_per']);
			$trace_options[$rule_num][] = "-m limit --limit-burst 1";
			
			foreach($rule['option'] as $opt => $val)
			{
				if(!empty($val))
				{
					if(strlen($opt) == 1)
					{
						$trace_options[$rule_num][] = "-".escapeshellarg($opt);
					}
					else
					{
						$trace_options[$rule_num][] = "--".escapeshellarg($opt);
					}
					$trace_options[$rule_num][] = escapeshellarg($val);
				}
			}

			$trace_options[$rule_num][] = preg_replace('/[^a-z0-9_\.\/! -]/i', '', $rule['custom']);
			$trace_options[$rule_num][] = "-j TRACE";
			
			if($rule['direction']['in'] == "1")  $trace_chains[$rule_num][] = 'PREROUTING';
			if($rule['direction']['out'] == "1") $trace_chains[$rule_num][] = 'OUTPUT';
		}


		$sysctl_cmd = "sysctl";
		$code = 0;
		if(!which("sysctl")) $sysctl_cmd = "/sbin/sysctl";
		if(run("$sysctl_cmd -n net.netfilter.nf_log.2") !== "ipt_LOG")
		{
			exec("sudo $sysctl_cmd net.netfilter.nf_log.2=ipt_LOG 2>&1", $stdout_array, $code);
		}
		if($code == 0)
		{
			$ok = iptables("raw", "F", "PREROUTING", array(), $stdout) && iptables("raw", "F", "OUTPUT", array(), $stdout);
			if($ok)
			{
				foreach($trace_options as $rule_num => $rule)
				{
					foreach($trace_chains[$rule_num] as $chain)
					{
						$ok = iptables("raw", "A", $chain, $rule, $stdout);
						if(!$ok)
						{
							$GLOBALS['text'] .= $stdout.PHP_EOL;
							iptables("raw", "F", "PREROUTING", array(), $stdout);
							iptables("raw", "F", "OUTPUT", array(), $stdout);
							break;
						}
					}
				}
				if($ok)
				{
					$GLOBALS['text'] .= "TRACE installed".PHP_EOL;
				}
			}
			else
			{
				$GLOBALS['text'] .= "Error".PHP_EOL.$stdout.PHP_EOL;
			}
			
			$Response = array(
				"firewall" => array(
					"raw" => iptables_save(),
				),
			);
			$Response["firewall"]["html"] = htmlize($Response["firewall"]["raw"]);
		}
		else
		{
			$stdout = implode(PHP_EOL, $stdout_array);
			$GLOBALS['text'] .= "Error".PHP_EOL.$stdout.PHP_EOL;
		}
	break;

	case "stop":
		$ok = iptables("raw", "F", "PREROUTING", array(), $stdout) && iptables("raw", "F", "OUTPUT", array(), $stdout);
		$GLOBALS['text'] .= $ok ? "TRACE removed" : "Error".PHP_EOL.$stdout.PHP_EOL;
	break;
	
	case "poll":
		session_start();
		
		$packets = array();
		$pos = isset($_SESSION["pos"]) ? $_SESSION["pos"] : 0;
		
		if($fh = fopen($logfile, 'r'))
		{
			fseek($fh, $pos-1, SEEK_SET);
			fread($fh, 1);
			if(feof($fh))
			{
				$pos = 0;
				fseek($fh, $pos, SEEK_SET);
			}
			while($line = fgets($fh))
			{
				/* <4>Aug 30 16:07:07 kernel: [1580709.330098] TRACE: filter:service-accept:rule:4 IN=br0 OUT= PHYSIN=eth0 MAC=00:0e:2e:e5:46:fb:e4:48:c7:80:71:11:08:00 SRC=79.112.67.90 DST=192.168.32.11 LEN=131 TOS=0x00 PREC=0x00 TTL=117 ID=25346 PROTO=UDP SPT=36688 DPT=51414 LEN=111 */
				if(preg_match('/TRACE: (\S+):(\S+):(\S+):(\S+) (.+)/', $line, $match))
				{
					$map = array(
						"table" => $match[1],
						"chain" => $match[2],
						"level" => $match[3],
						"number" => $match[4],
						"fields" => $match[5],
					);
					preg_match('/(?:^|\s)ID=([^0]\d*)/', $match[5], $match_id);
					$packet_id = $match_id[1];

					$packets[$packet_id][] = $map;
				}
			}
			$_SESSION["pos"] = ftell($fh);
			fclose($fh);
		}
		else
		{
			$GLOBALS['text'] .= "Can not open: $logfile".PHP_EOL;
		}
		
		$Response = array(
			"packets" => $packets,
		);
	break;
}


$Response["text"] = $GLOBALS['text'];
echo json_encode($Response);

