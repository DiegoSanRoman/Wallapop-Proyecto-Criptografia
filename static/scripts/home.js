// Obtener elementos del DOM
const profileImg = document.getElementById('profile-img');
const dropdownMenu = document.getElementById('dropdown-menu');

// Función para mostrar/ocultar el menú desplegable
profileImg.addEventListener('click', () => {
    dropdownMenu.style.display = dropdownMenu.style.display === 'block' ? 'none' : 'block';
});

// Cerrar el menú si se hace clic fuera de él
window.addEventListener('click', (event) => {
    if (!event.target.matches('#profile-img')) {
        dropdownMenu.style.display = 'none';
    }
});
