const main_nav_item = document.querySelectorAll('.main-nav-item a');
let i;

main_nav_item.forEach((element,index) => {
    element.setAttribute('onclick','addActiveClass(this)')
});

const addActiveClass = (param) => {
    console.log(param)
}