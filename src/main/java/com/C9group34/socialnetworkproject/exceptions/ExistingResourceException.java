package com.C9group34.socialnetworkproject.exceptions;

public class ExistingResourceException extends Exception{


    public static final String MESSAGE = "El recurso se está intentando crear ya existe.";

    public  ExistingResourceException() {
    }

    public ExistingResourceException(String message) {
        super(message);
    }
}

