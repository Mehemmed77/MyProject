const fileInput = document.querySelector('#id_image');
const image = document.querySelector('.profile-image');

let value;

const changeImage = (event) => {
    image.src = URL.createObjectURL(event.target.files[0])
}