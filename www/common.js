const $ = document.querySelector.bind(document)
const $$ = document.querySelectorAll.bind(document)

Object.values = function (obj) {
    var vals = [];
    for (var key in obj) {
        if (obj.hasOwnProperty(key)) {
            vals.push(obj[key]);
        }
    }
    return vals;
}

var query = findGetParameter("query") || "";
var page = findGetParameter("page") || "0";
var pages = 0;
if(typeof pagein != "undefined" && pagein.value !== null){
    pagein.value = parseInt(page)+1;
}

var baseUrl = window.location.protocol + "//" + window.location.hostname;

if (window.localStorage.getItem("token") != null) {
    $(".listitem.login").style.display = "none";
} else {
    $(".listitem.logout").style.display = "none";
    $(".listitem.addbot").style.display = "none";
    $(".listitem.profile").style.display = "none";
}

function findGetParameter(parameterName) {
    var result = null,
        tmp = [];
    location.search
        .substr(1)
        .split("&")
        .forEach(function (item) {
            tmp = item.split("=");
            if (tmp[0] === parameterName) result = decodeURIComponent(tmp[1]);
        });
    return result;
}

var instance = axios.create({
    validateStatus: a => {
        return true;
    }
});

var whoami = null;
if (localStorage.getItem("token") !== null) {
    instance.get(baseUrl + "/api/whoami", {
        "headers": {
            "Content-Type": "application/json",
            "Authorization": localStorage.getItem("token")
        }
    }).then(function (response) {
        whoami = response.data;
        if (response.status == "401") {
            localStorage.removeItem("token");
            window.location.href = baseUrl + "/login";
        }
        if (!whoami.admin) $(".listitem.verifynav").style.display = "none";
        window.whoami = whoami;
    });
} else {
    $(".listitem.verifynav").style.display = "none";
}

function next() {
    var url = baseUrl + window.location.pathname + "?query=" + query + "&page=" + (parseInt(page) + 1) + "&limit="+findGetParameter("limit");
    window.location.href = url;
}

function previous() {
    var url = baseUrl + window.location.pathname + "?query=" + query + "&page=" + (parseInt(page) - 1) + "&limit="+findGetParameter("limit");
    window.location.href = url;
}

function go() {
    var url = baseUrl + window.location.pathname + "?query=" + query + "&page=" + Math.max(Math.min(parseInt(pagein.value) - 1, pages), 0) + "&limit="+findGetParameter("limit");
    window.location.href = url;
}

function login() {
    window.location.href = baseUrl + "/login";
}

function logout() {
    window.localStorage.removeItem("token");
    window.location.href = baseUrl;
}

function addbot() {
    window.location.href = baseUrl + "/add";
}

function profile() {
    window.location.href = baseUrl + "/dashboard";
}

function verify() {
    window.location.href = baseUrl + "/verify";
}

function home() {
    window.location.href = baseUrl;
}

function unverifiedInvite(invite) {
    if (confirm(`!!!WARNING!!!
This bot has NOT YET passed verification from our staff team.
Inviting this bot may potentially be dangerous, we don't know.
Please, do your research and keep safe.
We are not responsible for damages if you ignore this!
Do you wish to continue?`)) {
        window.open(invite, "_blank");
    }
}

function offboard(link) {
    if (confirm(`!!!WARNING!!!
You are leaving the YABL site to go to:
${link}
Which is not controlled by the YABL team.
Do you wish to continue?`)) {
        window.open(link, "_blank");
    }
}

$(".searchbox").addEventListener("keyup", function (event) {
    event.preventDefault();
    if (event.keyCode === 13) {
        window.location.href = baseUrl + "/search?query=" + encodeURI($(".searchbox").value);
    }
});
