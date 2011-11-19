function show_cert(certid, el) {
	$.getJSON('/certinfo.json/'+certid, function(data) {
			alert(data['subject']);
	});
}
