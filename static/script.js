const searchInput = document.getElementById('search');
    const contactRows = document.querySelectorAll('.contact-info');

    searchInput.addEventListener('input', function() {
        const searchTerm = searchInput.value.toLowerCase();

        contactRows.forEach(row => {
            const regNo = row.dataset.reg_no.toLowerCase(); 

            if (regNo.includes(searchTerm)) { 
                row.style.display = "table-row";  
            } else {
                row.style.display = "none"; 
            }
        });
    });