<?php
/*
  REQUIREMENTS
   + sysctl net.netfilter.nf_log.2 = ipt_LOG
   + sudoers rules
      + USER ALL=(root) NOPASSWD: /sbin/iptables-save ""
      + USER ALL=(root) NOPASSWD: /sbin/iptables -t raw -F PREROUTING
	  + USER ALL=(root) NOPASSWD: /sbin/iptables -t raw -A PREROUTING * -j TRACE
	  Where USER is unix user running this script (eg. www-data for apache)
   + read access to $logfile for USER
   + do not modify firewall while tracing
*/
 
$logfile = "/var/log/iptables.log";
$Response = array();
$GLOBALS['text'] = '';

function iptables($table, $action, $chain, $options = array(), &$stdout = array())
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
	exec($cmd, $stdout, $code);
	if(@$_REQUEST["debug"])
	{
		$GLOBALS['text'] .= print_r($stdout, true);
	}
	return $code == 0;
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
		$trace_options = array();
		foreach($_REQUEST['filter']['option'] as $opt => $val)
		{
			if(!empty($val))
			{
				if(strlen($opt) == 1)
				{
					$trace_options[] = "-".escapeshellarg($opt);
				}
				else
				{
					$trace_options[] = "--".escapeshellarg($opt);
				}
				$trace_options[] = escapeshellarg($val);
			}
		}
		$trace_options[] = preg_replace('/[^a-z0-9_\.\/! -]/i', '', $_REQUEST['filter']['custom']);
		$trace_options[] = "-m limit --limit-burst 1 --limit 1/sec -j TRACE";
		
		$ok = iptables("raw", "F", "PREROUTING", array(), $stdout) && iptables("raw", "A", "PREROUTING", $trace_options, $stdout);
		$GLOBALS['text'] .= $ok ? "TRACE installed" : "Error".PHP_EOL.$stdout;
		
		$Response = array(
			"firewall" => array(
				"raw" => iptables_save(),
			),
		);
		$Response["firewall"]["html"] = htmlize($Response["firewall"]["raw"]);
	break;

	case "stop":
		$ok = iptables("raw", "F", "PREROUTING", array(), $stdout);
		$GLOBALS['text'] .= $ok ? "TRACE removed" : "Error".PHP_EOL.$stdout;
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
			$GLOBALS['text'] .= "Can not open: $logfile";
		}
		
		$Response = array(
			"packets" => $packets,
		);
	break;
}


$Response["text"] = $GLOBALS['text'];
echo json_encode($Response);

