function delete_cert(certid) {
	$.del('/certificate/'+certid, function(message) {
		alert(message);
	})
}
