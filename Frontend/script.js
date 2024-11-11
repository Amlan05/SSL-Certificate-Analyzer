document.getElementById('ssl-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const hostname = document.getElementById('hostname').value;
    const resultDiv = document.getElementById('result');
    
    // Clear previous results
    resultDiv.textContent = 'Checking...';
    resultDiv.className = '';

    // Use the full URL to the backend API on Railway
    fetch('https://ssl-certificate-analyzer-production.up.railway.app/check_ssl', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hostname: hostname })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const cert = data.certificate;
            resultDiv.innerHTML = `
                <p><strong>Hostname:</strong> ${hostname}</p>
                <p><strong>IP Address:</strong> ${cert.ip_address}</p>
                <p><strong>Issued By:</strong> ${cert.issued_by}</p>
                <p><strong>Server Type:</strong> ${cert.server_type}</p>
                <p><strong>Expiration Date:</strong> ${cert.expiration_date}</p>
                <p><strong>Days Left:</strong> ${cert.days_left} days</p>
                <p><strong>Hostname Verified:</strong> ${cert.hostname_verified ? 'Yes' : 'No'}</p>
            `;
            resultDiv.className = 'success';
        } else {
            resultDiv.textContent = `The website ${hostname} does not have a valid SSL certificate.`;
            resultDiv.className = 'error';
        }
    })
    .catch(error => {
        resultDiv.textContent = 'An error occurred. Please try again later.';
        resultDiv.className = 'error';
    });
});
