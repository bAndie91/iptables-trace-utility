	
	function starttraceing()
	{
		$('#firewall').html('');
		clear_packetlist();
		clear_resultbox();

		var filters = [];
		$('.filter_div').each(function()
		{
			var filter = {option:{}, custom:{}};
			$(this).find('.filter_option').each(function()
			{
				filter.option[this.name] = this.value;
			});
			filter.custom = $(this).find('.filter_custom').val();
			filter.direction = {
				'in':  $(this).find('[name=direction_in]').attr('checked')  ? 1 : 0,
				'out': $(this).find('[name=direction_out]').attr('checked') ? 1 : 0,
			};
			
			filters.push(filter);
		});
		
		$.post(
			AJAXURL,
			{
				act: 'setup',
				filters: filters,
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
					
					var anchor = $('<a href="javascript:select_packet(' + pktid + ');" data-pktid=' + pktid + '>' + pktid + '</a>');
					var title = document.packet_data[pktid][0].fields;
					anchor.attr('title', title);
					anchor.tooltip(document.ui_tooltip_defaults);
					anchor.tooltip({content: title.replace(/\s+/g, "<br/>")});
					
					$('#packet_list').append(anchor);
					$('#packet_list').append(' ');
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
	
	function scrolltorule(event)
	{
		$('#firewall > span').each(function()
		{
			$(this).removeClass('hilight2');
		});

		var selector = event.data.selector;
		$('#firewall').slideDown(
			400,
			function() {
				$('html, body').animate(
					{ scrollTop: $(selector).offset().top }, 
					1000, 
					null, 
					function() {
						hilight($(selector), 2);
					}
				);
			});
	}
	
	function select_packet(pktid)
	{
		clear_hilights();
		$('#packet_list a').removeClass('hilit');
		$('#packet_list a[data-pktid='+pktid+']').addClass('hilit');

		var pkt = document.packet_data[pktid];
		var trace_result_table = $('<table/>');
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
					selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"]:not([rule])';
				}
			}
			else if(step.level == 'rule')
			{
				selector = 'span[table="' + step.table + '"][chain="' + step.chain + '"][rule="' + step.number + '"]';
			}
			hilight($(selector));
			
			var hit_text = step.table+':'+step.chain+':'+step.level+':'+step.number;
			var rule_text = $(selector).text();
			var hit_span = $('<span class="trace_hit">'+hit_text+'</span>');
			var rule_span = $('<span class="trace_rule">'+rule_text+'</span>');
			hit_span.attr('title', rule_text);
			rule_span.attr('title', hit_text);
			if($('#trace_result .trace_rule').is(':visible')) hit_span.hide();
			else rule_span.hide();
			var anchor = $('<a href="javascript:;"></a>');
			anchor.click({selector: selector}, scrolltorule);
			anchor.append(hit_span);
			anchor.append(rule_span);
			var row = $('<tr><td class="trace_step"></td></td><td class="trace_details">'+step.fields+'</td></tr>');
			row.find('.trace_step').append(anchor);
			trace_result_table.append(row);
		}
		clear_resultbox();
		$('#trace_result').append(trace_result_table);
		$('#trace_result a span').tooltip(document.ui_tooltip_defaults);
		$('#trace_result a span').tooltip({delay: 250});
		$('#trace_result').slideDown();
	}
	
	function switch_trace_hit_rule()
	{
		$('#trace_result .trace_hit').toggle();
		$('#trace_result .trace_rule').toggle();
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

	function addfilterdiv()
	{
		var lastfilterdiv = $('.filter_div').last();
		var newdiv = lastfilterdiv.clone();
		var filterdiv_num = $('.filter_div').length + 1;
		newdiv.attr('filterdiv_num', filterdiv_num);
		newdiv.find('.filter_direction').each(function()
		{
			var attr = $(this).is('label') ? 'for' : 'id';
			var m = $(this).attr(attr).match(/^(.*_)([0-9]+)$/);
			$(this).attr(attr, m[1] + filterdiv_num);
		});
		newdiv.find('.delfilterdiv').remove();
		newdiv.append('<input type=button value="&ndash;" class="delfilterdiv" onClick="delfilterdiv(' + filterdiv_num + ');" />');
		lastfilterdiv.parent().append(newdiv);
	}

	function delfilterdiv(filterdiv_num)
	{
		$('.filter_div[filterdiv_num=' + filterdiv_num + ']').remove();
	}
	
	$(document).ready(function()
	{
		document.packet_data = {};
		
		document.ui_tooltip_defaults = {
			show: false, 
			hide: false, 
			track: true, 
			tooltipClass: "mytooltip", 
			position: {
				my: "left+15 center", 
				at: "right center", 
				offset: "flipfit flipfit"
			},
		};
		
		$('input[length].filter_option, input[length].filter_custom').each(function()
		{
			this.style.width = $(this).attr('length') * 8;
		});
		
		$('legend > span').click(function() {
			$(this).parent().siblings().slideToggle("slow");
		});
	});
