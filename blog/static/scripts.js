// detal.html
$(document).ready(function () {
    $(".post-container").hover(
        function () {
            // وقتی موس روی متن قرار گرفت
            $(".post-container").css("background", "rgba(255, 255, 255, 0.8)");
        },
        function () {
            // وقتی موس از روی متن حرکت کرد
            $(".post-container").css("background", "none");
        }
    );
});
