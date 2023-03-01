package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/users")
@CrossOrigin
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTutil jwt;


    @PostMapping("/new")
    @Operation(
            summary = "Create new use",
            description = "With endpoint can you created a new user",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "created"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity register (@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"Luis\", \"surname\" : \"Uzcategui\", \"email\" : \"luis@example.com\", \"password\" : \"123456789\", \"phone\" : \"+593979010717\", \"img_profile\" : \"URL\" }"
                    )
            )
    ) @RequestBody UserDto u){

        User user = null;
        try {
            user = userService.register(u);
        } catch (ExistingResourceException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_IMPLEMENTED);
        }

        return new ResponseEntity(user, HttpStatus.CREATED);

    }

    @GetMapping("/all")
    @Operation(
            summary = "Get all users",
            description = "This endpoint is for get all users",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "getAll"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity retrieve(){

        return new ResponseEntity(userService.retrieveAll(), HttpStatus.OK);
    }

    @GetMapping("/get")
    @Operation(
            security = @SecurityRequirement(name = "token"),
            summary = "Get a user",
            description = "This endpoint is for get a user by token"
    )
    public ResponseEntity<UserDto> retrieveUser(@RequestHeader(value = "Authorization") String token){

        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)) {
            UserDto user = null;
            try {
                user = userService.retrieveById(Integer.valueOf(id));
            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
                return new ResponseEntity("el usuario no ha sido encontrado", HttpStatus.NOT_FOUND);
            }
            return new ResponseEntity(user, HttpStatus.OK);
        }
        return new ResponseEntity("Acceso denegado", HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/delete")
    @Operation(
            summary = "Delete a user",
            description = "This endpoint is for delete a user",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "userDeleted"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity delete(@RequestHeader(value = "Authorization") String token) {

        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)) {
            try {
                userService.delete(Integer.valueOf(id));
                return new ResponseEntity(HttpStatus.OK);
            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
                return new ResponseEntity("Accion no realizada", HttpStatus.NOT_IMPLEMENTED);
            }
        }
        return new ResponseEntity("Acceso denegado", HttpStatus.UNAUTHORIZED);

    }

    @PutMapping("/edit")
    @Operation(
            summary = "Update a user",
            description = "This endpoint is for update a user",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "userUpdated"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity replace(@RequestHeader(value = "Authorization") String token,@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"String\", \"surname\" : \"String\", \"email\" : \"String\", \"password\" : \"String\", \"phone\" : \"String\", \"ratings\" : 0.0, \"imgProfile\" : \"String\" }"
                    )
            )
    ) @RequestBody UserDto user) {
        String id = jwt.getKey(token);
        try {
            if(jwt.verifyToken(token)){
                userService.replace(Integer.valueOf(id), user);
                return new ResponseEntity<>("Datos Actualizados", HttpStatus.OK);
            }
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_MODIFIED);
        }
        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }
}

