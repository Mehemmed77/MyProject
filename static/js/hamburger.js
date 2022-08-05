const modal = document.getElementById('hamburger-modal');
const trigger = document.getElementById('trigger');
const navContainer = document.getElementById('nav-container');
const modalHeader = document.getElementsByClassName('modal-header')[0];

trigger.onclick = () => {
    modal.style.display = 'block';

    setTimeout(() => {
        navContainer.style.left = '0px';
        modalHeader.style.left = '0%';
    },200);

};

window.onclick = function(event){
    if(event.target==modal){
        navContainer.style.left = '-280px';
        modalHeader.style.left = '-100%';

        setTimeout(() => {
            modal.style.display = 'none';
        },500)
    };
};

