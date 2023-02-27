package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.models.Token;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.util.Objects;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthUserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTutil jwt;

    @PostMapping("/login")
    @Operation(
            summary = "Login user",
            description = "This endpoint is for loged to user",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "login"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity loginUser(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{ \"email\": \"luis@example.com\", \"password\" : \"1234\" }"
                    )
            )
    ) @RequestBody UserDto userDto) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {

        Optional<User> checkedUser = Optional.ofNullable(userService.getUserByEmail(userDto.getEmail()));
        if(checkedUser.isEmpty()){
            return new ResponseEntity<>("EMAIL INORRECT", HttpStatus.UNAUTHORIZED);
        }
        User u = checkedUser.get();
        if(!Objects.equals(u.getPassword(), userDto.getPassword())){
            return new ResponseEntity<>("PASSWORD INCORRECT", HttpStatus.UNAUTHORIZED);
        }
        String t = jwt.create(String.valueOf(u.getId()), u.getEmail()); // generando un
        // token devuelto para ser almacenado en cliente
        return new ResponseEntity(new Token(t),HttpStatus.OK );
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
    @Operation(
            responses = {
                    @ApiResponse(responseCode = "200",ref = "login")
            }
    )
    public Token guestToken(){
        Token token = new Token(jwt.create("0000", "xxx"));
        return token;
    }

}