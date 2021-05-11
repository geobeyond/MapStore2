import queryString from 'query-string';
import axios from 'axios';
import qs from 'qs';

class Auth {
    props = {};

    constructor(props) {
        this.props = { ...this.props, ...props };
        this.isAuthenticated = this.isAuthenticated.bind(this);
        this.login = this.login.bind(this);
        this.handleAuthentication = this.handleAuthentication.bind(this);
        this.logout = this.logout.bind(this);
    }

    login() {
        console.log("[STF] Auth.login()");
        sessionStorage.setItem('redirectUri', window.location.href);
        var url = this.props.authorize
            + "?response_type=code"
            + "&client_id=" + this.props.clientId
            + "&scope=openid profile" //email offline_access api
            + "&nonce=13e2312637dg136e1"
            + "&state=13e2312637dg136e1"
            + "&redirect_uri=" + window.location.origin + "/";
        window.location.href = url;
    }

    logout() {
        console.log("[STF] Auth.logout()");
        sessionStorage.setItem('redirectUri', window.location.href);
        axios({
            method: 'POST',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'content-type': 'application/x-www-form-urlencoded'
            },
            data: qs.stringify({
                token: sessionStorage.getItem('accessToken'),
                token_type_hint: 'access_token',
                client_id: this.props.clientId,
            }),
            url: this.props.revoke,
        })
            .then((response) => {
                console.log("[STF] response:", response);
                var url = this.props.logout
                    + "?id_token_hint=" + sessionStorage.getItem('idToken')
                    + "&post_logout_redirect_uri=" + window.location.origin + "/";
                window.location.href = url;
            })
            .catch(error => {
                console.error("[STF] error:", error);
                var url = this.props.logout
                    + "?id_token_hint=" + sessionStorage.getItem('idToken')
                    + "&post_logout_redirect_uri=" + window.location.origin + "/";
                window.location.href = url;
            });

    }

    handleAuthentication() {
        const authResult = queryString.parse(window.location.search);
        if (authResult.code) {
            console.log("[STF] Auth.handleAuthentication() handle login callback");
            sessionStorage.removeItem('accessToken');
            sessionStorage.removeItem('refreshToken');
            sessionStorage.removeItem('idToken');
            sessionStorage.removeItem('userinfo');
            axios({
                method: 'POST',
                headers: {
                    'Accept': 'application/json, text/plain, */*',
                    'content-type': 'application/x-www-form-urlencoded'
                },
                data: qs.stringify({
                    grant_type: 'authorization_code',
                    code: authResult.code,
                    client_id: this.props.clientId,
                    redirect_uri: window.location.origin + "/",
                    //code_verifier: 'zcXQbIQxmaJkV26QkmV9TtIt0E3iBszdXBZ2nf61jt_zT'
                }),
                url: this.props.token,
            })
                .then((response) => {
                    console.log("[STF] response:", JSON.stringify(response));
                    sessionStorage.setItem('accessToken', response?.data?.access_token);
                    sessionStorage.setItem('refreshToken', response?.data?.refresh_token);
                    sessionStorage.setItem('idToken', response?.data?.id_token);
                    axios({
                        method: 'GET',
                        headers: {
                            'Accept': 'application/json, text/plain, */*',
                            'Authorization': 'Bearer ' + sessionStorage.getItem('accessToken'),
                        },
                        url: this.props.userinfo,
                    })
                        .then((response) => {
                            console.log("[STF] response:", JSON.stringify(response));
                            sessionStorage.setItem('userinfo', JSON.stringify(response?.data));
                            window.location.replace(sessionStorage.getItem('redirectUri'));
                        })
                        .catch(error => {
                            console.error("[STF] error:", error);
                        });
                })
                .catch(error => {
                    console.error("[STF] error:", error);
                });
        } else if (authResult.sp) {
            console.log("[STF] Auth.handleAuthentication() handle logout callback");
            sessionStorage.removeItem('accessToken');
            sessionStorage.removeItem('refreshToken');
            sessionStorage.removeItem('idToken');
            sessionStorage.removeItem('userinfo');
            if (sessionStorage.getItem('redirectUri')) {
                window.location.replace(sessionStorage.getItem('redirectUri'));
            }
        }
    }

    isAuthenticated() {
        let retValue = sessionStorage.getItem("accessToken") != null;
        return retValue;
    }

    hasRealmRole(role) {
        if (this.isAuthenticated()) {
            const userinfo = sessionStorage.getItem("userinfo");
            if (userinfo?.includes(role)) {
                return true;
            }
        }
        return false;
    }

    username() {
        if (this.isAuthenticated()) {
            const userinfo = sessionStorage.getItem("userinfo");
            if (userinfo) {
                return JSON.parse(userinfo)?.sub;
            }
        }
        return null;
    }
}

export default Auth;