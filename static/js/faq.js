function show(element) {
    var answer = element.querySelector("answer");
    element.style.height = "100px"; // Increase the height
    answer.hidden = false;
}

function hide(element) {
    var answer = element.querySelector("answer");
    element.style.height = "50px"; // Reset the height
    answer.hidden = true;
}