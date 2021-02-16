package com.sacareers.gateway.exception;

import lombok.Data;

@Data
public class GatewayException extends RuntimeException{

    private String message;

    public GatewayException(String message){
        super(message);
        this.message = message;
    }
}
