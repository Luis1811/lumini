package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.FavoritePublicationDto;

import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;

import com.C9group34.socialnetworkproject.service.FavoritePublicationService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/favorites")
@CrossOrigin
public class FavoritePublicationController {

    @Autowired
    private FavoritePublicationService favoritePService;
    @Autowired
    private JWTutil jwt;

    @PostMapping("/{publicationId}")
    @Transactional
    public ResponseEntity create(@RequestHeader(value = "Authorization") String token,
                                 @PathVariable Integer publicationId) {

        FavoritePublicationDto favoriteDto = null;
        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)) {
            try {
                favoriteDto = favoritePService.create(Integer.valueOf(id), publicationId);
            } catch (ExistingResourceException e) {
                System.out.println(e.getMessage());
            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
            }
            return new ResponseEntity<>(favoriteDto, HttpStatus.CREATED);
        }
        return new ResponseEntity("Acceso denegado", HttpStatus.UNAUTHORIZED);
    }

    @GetMapping
    public ResponseEntity retrieve(@RequestHeader(value = "Authorization") String token) {

        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)) {
            try {
                return new ResponseEntity(favoritePService.retrieveAll(Integer.valueOf(id)), HttpStatus.OK);
            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
                return new ResponseEntity(HttpStatus.NOT_FOUND);
            }
        }

        return new ResponseEntity("Acceso denegado", HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/{favoritePublicationId}")
    public ResponseEntity delete(@RequestHeader(value = "Authorization") String token,
                                 @PathVariable Integer favoritePublicationId) {

        if (jwt.verifyToken(token)) {
            try {
                favoritePService.delete(favoritePublicationId);
            } catch (ResourceNotFoundException e) {
                throw new RuntimeException(e);
            }
            return new ResponseEntity(HttpStatus.OK);
        }
      return new ResponseEntity("Acceso denegado",HttpStatus.UNAUTHORIZED);
    }
}
