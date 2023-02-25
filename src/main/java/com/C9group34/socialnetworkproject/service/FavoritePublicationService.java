package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.FavoritePublicationDto;
import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.FavoritePublication;
import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.FavoritePublicationRepository;
import com.C9group34.socialnetworkproject.repository.PublicationRepository;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class FavoritePublicationService {
    @Autowired
    private FavoritePublicationRepository favoriteRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PublicationRepository publicationRepository;


    public FavoritePublicationDto create( Integer userId, Integer publicationId) throws ExistingResourceException, ResourceNotFoundException {
        Optional<User> u = userRepository.findById(userId);
        Optional<Publication> p = publicationRepository.findById(publicationId);
        System.out.println(p.get());
        if (u.isEmpty()) {
            throw new ResourceNotFoundException("usuario no encontrado");
        }
        Optional<Publication> publication = publicationRepository.findById(publicationId);
        if (p.isEmpty()) {
            throw new ResourceNotFoundException("publicacion no encontrada");
        }
        FavoritePublication fp = new FavoritePublication().builder()
                .publication(p.get())
                .user(u.get()).build();;
        fp = favoriteRepository.save(fp);
        return this.mapToDTO(fp);
    }

    public List<FavoritePublicationDto> retrieveAll(Integer userId) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está ingresando no existe.");
        }
        List<FavoritePublication> favoritePublications = favoriteRepository.findAll();
        return favoritePublications.stream()
                .map(favoritePublication -> mapToDTO(favoritePublication))
                .collect(Collectors.toList());
    }

    public void delete(Integer favoritePublicationId) throws ResourceNotFoundException {
        try {
            favoriteRepository.deleteById(favoritePublicationId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException();
        }
    }

    private FavoritePublication mapToEntity(User u, Publication p) {
        return new FavoritePublication().builder()
                .publication(p)
                .user(u).build();
    }

    private FavoritePublicationDto mapToDTO(FavoritePublication fp) {
        return new FavoritePublicationDto().builder()
                .publication(fp.getPublication())
                .user(fp.getUser()).build();
    }

}