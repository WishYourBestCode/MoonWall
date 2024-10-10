import React, {useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import '../styles/layout/home.css';


function Home(){
    useEffect(() => {
        console.log("Home");
    }, []);

    return (
        <>
            <div className="section">
                <img src={require("../../assets/stars.png")} id="stars"/>
                <img src={require("../../assets/moon.png")} id="moon"/>
                <img src={require("../../assets/mountains_behind.png")} id="mountains_behind"></img>
                <h2 id="text">Moon Wall</h2>
                <img src={require("../../assets/mountains_behind.png")} id="mountains_front"/>
            </div>
        </>

    )
}

export default Home