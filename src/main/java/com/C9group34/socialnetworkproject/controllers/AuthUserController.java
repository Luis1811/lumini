package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.models.Token;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthUserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTutil jwt;

    @PostMapping("/login")
    public Token loginUser(@RequestBody UserDto userDto) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {

        System.out.println(userDto.getId());
            User checkedUser = userService.getUserByEmail(userDto.getEmail());
            String t = jwt.create(String.valueOf(checkedUser.getId()), checkedUser.getEmail()); // generando un
                // token devuelto para ser almacenado en cliente
           return new Token(t);
    }

    @GetMapping("/logged")
    public boolean isLogged(@RequestHeader(value = "Authorization") String token) {

        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)){
            return true;
        }
        return false;
    }

    //-----------------------------



    @GetMapping(value = "auth/guest")
    public Token guestToken(){
        Token token = new Token(jwt.create("0000", "xxx"));
        return token;
    }

}