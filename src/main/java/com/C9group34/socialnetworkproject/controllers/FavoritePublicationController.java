package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.FavoritePublicationDto;
import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import com.C9group34.socialnetworkproject.service.FavoritePublicationService;
import com.C9group34.socialnetworkproject.service.PublicationService;
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



    @PostMapping
    @Transactional
    public ResponseEntity create(@PathVariable Integer userId,
                                 @RequestBody FavoritePublicationDto favoritePublicationDto) {

        favoritePService
                create(publicationDTO , userId);
        return new ResponseEntity<>(publicationDTO.getId(), HttpStatus.CREATED);
    }
}
