package com.C9group34.socialnetworkproject.exceptions;

public class ResourceNotFoundException extends Exception{
    public static final String MESSAGE = "El recurso que está buscando no existe.";

    public ResourceNotFoundException(){
        super(MESSAGE);
    }
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
