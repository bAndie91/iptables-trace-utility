# iptables-trace-utility

## Requirements

* `modprobe ipt_LOG`
* `sysctl net.netfilter.nf_log.2 = ipt_LOG`
* sudoers rules:

       USER ALL=(root) NOPASSWD: /sbin/iptables-save ""
       USER ALL=(root) NOPASSWD: /sbin/iptables -t raw -F *
       USER ALL=(root) NOPASSWD: /sbin/iptables -t raw -A * -j TRACE
       USER ALL=(root) NOPASSWD: /sbin/sysctl net.netfilter.nf_log.2=ipt_LOG

  Where *USER* is unix user running **ajax.php** script (eg. www-data when using apache)
* backend component:
  * webserver
    * you need a php-enabled webserver to run ajax.php, or
    * use php 5.4 embeded webserver by invoking this command in folder where you have unpacked files:
 
      `sudo -u `*`USER`*` php -S localhost:8080 -t .`
  * configure `$logfile` in **ajax.php** to point to file iptables is logging in (eg. /var/log/kern.log)
    * you can setup rsyslog to separate iptables' log messages:

        ```
        :msg, regex, "^\[[ ]*[0-9]*\.[0-9]*\] Firewall: "  -/var/log/iptables.log
        & ~
        :msg, regex, "^\[[ ]*[0-9]*\.[0-9]*\] TRACE: "     -/var/log/iptables.log
        & ~
        ```
* read access to `$logfile` for *USER* (eg. `chmod +r $logfile`)
* frontend component:
  * point AJAXURL variable to the right URL in JS code
  * jquery.js
  * jquery-ui.js
* do not modify firewall while tracing

## Usage

* Specity filter options in Filter box or leave empty to trace all packets.
* Pay attention to limit parameter, too high limit may lead to high load on target system!
* Press <kbd>TRACE!</kbd> to start tracing and <kbd>Stop</kbd> to finish it.
* The programm polls server every 1.5 sec for new trace results, you can press <kbd>Refresh</kbd> to poll them manually.
* Messages box: status and error messages from server
* Packet IDs will appear in Packets box during trace. Click on a packet ID to display steps in Trace box, whiches the packet has met in its way through the firewall.
* Firewall box: iptables-save output hilighting rules with which the selected packet has met.


## Screenshot

![screenshot](http://i.imgur.com/7Jnl7Fi.png)
