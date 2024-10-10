import React, {useEffect, useState} from "react";
import Form from 'react-bootstrap/Form';
import {Button} from "react-bootstrap";
import '../styles/layout/moonwall.css';
import WebSocketService from '../../utils/WebSocketService';
import ParentMoonWall from "./ParentMoonWall";


function Moonwall(){


    useEffect(() => {

    }, []);


    return (
        <>
            <div className="section">
                <img src={require("../../assets/stars.png")} id="stars"/>
                <ParentMoonWall />
            </div>
        </>
    );
}

export default Moonwall;