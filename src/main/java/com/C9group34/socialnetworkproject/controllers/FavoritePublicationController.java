package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.FavoritePublicationDto;

import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;

import com.C9group34.socialnetworkproject.service.FavoritePublicationService;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/favorites")
public class FavoritePublicationController {

    @Autowired
    private FavoritePublicationService favoritePService;

    @PostMapping("/{userId}/{publicationId}")
    @Transactional
    public ResponseEntity create(@PathVariable Integer userId,
                                 @PathVariable Integer publicationId) {

        FavoritePublicationDto favoriteDto = null;
        try {
            favoriteDto = favoritePService.create( userId, publicationId);
        } catch (ExistingResourceException e) {
            System.out.println(e.getMessage());
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
        }
        return new ResponseEntity<>(favoriteDto.getId(), HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity retrieve(@PathVariable Integer userId){

        try {
            return new ResponseEntity(favoritePService.retrieveAll(userId), HttpStatus.OK);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/{favoritePublicationId}")
    public ResponseEntity delete(@PathVariable Integer favoritePublicationId){
        try {
            favoritePService.delete(favoritePublicationId);
        } catch (ResourceNotFoundException e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity(HttpStatus.OK);
    }
}
