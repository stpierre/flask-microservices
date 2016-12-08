var initialSlide;
var isOverview;

Reveal.addEventListener('ready', function(event) {
    initialSlide = event.currentSlide;
});


$(document).ready(function() {
    $('[data-toggle="tooltip"]').tooltip(
        {"placement": "left", "trigger": "click", "html": true,
         "container": "body"});

    var tooltipContainer = $("div.reveal")
    $.each($('div.tooltip-buttons'), function(i, value) {
        var element = $(value);
        element.attr("tooltips-for", element.parent()[0].id);
        tooltipContainer.append(element.detach());
    });

    Reveal.addEventListener('slidechanged', function(event) {
        if (!Reveal.isOverview()) {
            $('.tooltip').hide();
            $('div[tooltips-for="' + event.currentSlide.id + '"]')
                .css("display", "block");
            $('div[tooltips-for="' + event.previousSlide.id + '"]')
                .css("display", "none");
        }
    });

    Reveal.addEventListener('overviewshown', function(event) {
        $('.tooltip').not(this).hide();
        $('div.tooltip-buttons').css("display", "none");
    });

    Reveal.addEventListener('overviewhidden', function(event) {
        $('div[tooltips-for="' + event.currentSlide.id + '"]')
            .css("display", "block");
    });

    $('div[tooltips-for="' + initialSlide.id + '"]').css("display", "block");
})
