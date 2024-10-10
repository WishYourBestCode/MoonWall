import fetch from "Axios";
const baseURL = "localhost:8888"
export const moonWall = {
    index() {
        return fetch(`${baseURL}/firwall`, {
            method: "GET",
            credentials: "include"
        }).then(res => res.json());
    },
    show(id) {
        return fetch(`${baseURL}/products/${id}`, {
            method: "GET",
            credentials: 'include'
        }).then(res => res.json())
    },
    create(params){
        return fetch(`${baseURL}/`, {
            method: 'POST',
            credentials:'include',
            headers:{
                'Content-Type':'application/json'
            ,
            body: JSON.stringify(params)

        }}).then(res => res.json());
    },
    async createMoonWal(e, params) {
        e.preventDefault();
        try {
            await fetch("http://"+`${baseURL}`+"/send", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({message}),
            });
            // Handle response...
        } catch (error) {
            console.error('Error:', error);
        }
    }
}

