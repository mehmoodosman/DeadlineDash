// static/script.js
document.addEventListener('DOMContentLoaded', function() {
    const loadDataBtn = document.getElementById('loadDataBtn');
    const dataContainer = document.getElementById('dataContainer');

    loadDataBtn.addEventListener('click', function() {
        fetch('/api/data')
            .then(response => response.json())
            .then(data => {
                dataContainer.innerHTML = `<p>${data.message}</p>`;
            })
            .catch(error => console.error('Error:', error));
    });
});
