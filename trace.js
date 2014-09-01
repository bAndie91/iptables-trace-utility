	
	AJAXURL = 'ajax.php';
	
	function starttraceing()
	{
		$('#firewall').html('');
		clear_packetlist();
		clear_resultbox();

		var filter = {option:{}, custom:{}};
		$('.filter_option').each(function()
		{
			filter.option[this.name] = this.value;
		});
		filter.custom = $('.filter_custom').val();
		
		$.post(
			AJAXURL,
			{
				act: 'setup',
				filter: filter,
				debug: $('#chkb_debug').attr('checked') ? 1 : 0,
			},
			function(data, textStatus, xhr)
			{
				$('#rawoutput').text(data.text);
				$('#firewall').html(data.firewall.html);
				document.trace_timer = setInterval(refresh, 1500);
			},
			'json'
		);
	}
	
	function refresh()
	{
		$.getJSON(
			AJAXURL,
			{
				act: 'poll',
			},
			function(data, textStatus, xhr)
			{
				// console.log(data);
				if(data.text)
				{
					$('#rawoutput').text(data.text);
				}
				for(var pktid in data.packets)
				{
					$('#packet_list a[data-pktid='+pktid+']').remove();
					if(document.packet_data[pktid])
					{
						for(var stepid in data.packets[pktid])
						{
							document.packet_data[pktid].push(data.packets[pktid][stepid]);
						}
					}
					else
					{
							document.packet_data[pktid] = data.packets[pktid];
					}
					$('#packet_list').append('<a href="javascript:select_packet(' + pktid + ');" data-pktid=' + pktid + '>' + pktid + '</a> ');
				}
			}
		);
	}

	function hilight(obj, hilightlevel)
	{
		obj.each(function()
		{
			$(this).addClass('hilight' + (hilightlevel ? hilightlevel : '1'));
		});
	}

	function clear_hilights()
	{
		$('#firewall > span').each(function()
		{
			$(this).removeClass('hilight1');
			$(this).removeClass('hilight2');
		});
	}
	
	function clear_packetlist()
	{
		$('#packet_list').html('');
	}
	
	function clear_resultbox()
	{
		$('#trace_result').html('');
	}
	
	function scrolltorule(selector_encoded)
	{
		$('#firewall > span').each(function()
		{
			$(this).removeClass('hilight2');
		});

		var selector = decodeURI(selector_encoded);
		$('html, body').animate({scrollTop: $(selector).offset().top}, 1000, null, function(){ hilight($(selector), 2); });
	}
	
	function select_packet(pktid)
	{
		clear_hilights();
		clear_resultbox();
		
		var pkt = document.packet_data[pktid];
		var trace_result_html = '<table>';
		for(var stepid in pkt)
		{
			var step = pkt[stepid];
			var selector;

			if(step.level == 'policy')
			{
				selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"]:not([rule])';
			}
			else if(step.level == 'return')
			{
				selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"][rule="' + step.number + '"]';
				if($(selector).length == 0)
				{
					selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"]';
				}
			}
			else if(step.level == 'rule')
			{
				selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"][rule="' + step.number + '"]';
			}
			hilight($(selector));
			trace_result_html += '<tr><td class="trace_hit"><a href="javascript:scrolltorule(\''+encodeURI(selector)+'\');">'+step.table+':'+step.chain+':'+step.level+':'+step.number+'</a></td><td class="trace_details">'+step.fields+'</td></tr>';
		}
		trace_result_html += '</table>'
		$('#trace_result').html(trace_result_html);
	}
	
	function stoptraceing()
	{
		clearInterval(document.trace_timer);
		$.post(
			AJAXURL,
			{
				act: 'stop',
			},
			function(data, textStatus, xhr)
			{
				$('#rawoutput').text(data.text);
			},
			'json'
		);
	}
	
	$(document).ready(function()
	{
		document.packet_data = {};
		
		$('input[length].filter_option, input[length].filter_custom').each(function()
		{
			this.style.width = $(this).attr('length') * 8;
		});
	});
