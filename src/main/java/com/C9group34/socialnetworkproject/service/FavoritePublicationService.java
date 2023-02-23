package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.FavoritePublicationDto;
import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.FavoritePublication;
import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.FavoritePublicationRepository;
import com.C9group34.socialnetworkproject.repository.PublicationRepository;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class FavoritePublicationService {
    @Autowired
    private FavoritePublicationRepository favoriteRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PublicationRepository publicationRepository;

    public FavoritePublication create(FavoritePublicationDto fpDto, Integer userId, Integer publicationId) throws ExistingResourceException, ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        Optional<Publication> publication = publicationRepository.findById(publicationId);
        if (publication.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        FavoritePublication fp = mapToEntity(fpDto, user.get(), publication.get());
        fp = favoriteRepository.save(fp);
        return fp;
    }

    private FavoritePublication mapToEntity(FavoritePublicationDto favoritePublicationDto, User u, Publication p) {
        FavoritePublication favoritePublication = new FavoritePublication().builder()
                .publication(p)
                .user(u).build();
        return favoritePublication;
    }

}
