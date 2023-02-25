package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.PublicationRepository;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class PublicationService {


    // ------------cambio por autowired por simplicidad de codigo---------------
    @Autowired
    private  PublicationRepository publicationRepository;
    @Autowired
    private  UserRepository userRepository;


    public void create(PublicationDto publicationDTO, Integer userId) {
        Optional<User> user = userRepository.findById(userId);
        Publication publication = mapToEntity(publicationDTO, user.get());
        publicationRepository.save(publication);
    }


    public List<PublicationDto> retrieveAll(Integer userId) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está ingresando no existe.");
        }
        List<Publication> publications = publicationRepository.findAll();
        return publications.stream()
                .map(publication -> mapToDTO(publication))
                .collect(Collectors.toList());
    }

    public PublicationDto retrieveById(Integer publicationId) throws ResourceNotFoundException {
        Optional<Publication> publication = publicationRepository.findById(publicationId);

        if (publication.isEmpty()) {
            throw new ResourceNotFoundException("El id de la publicacion que está buscando no existe.");
        }
        return mapToDTO(publication.get());
    }


    public void delete(Integer publicationId) throws ResourceNotFoundException {
        try {
            publicationRepository.deleteById(publicationId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException();
        }
    }

    public void replace(Integer userId, Integer publicationId , PublicationDto publicationDto) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está ingresando no existe.");
        }
        Optional<Publication> publication = publicationRepository.findById(publicationId);
        if (publication.isEmpty()) {
            throw new ResourceNotFoundException("El id de la publicacion que está ingresando no existe.");
        }

        Publication updatedPublication;
        Publication publicationToReplace = publication.get();
        updatedPublication = new Publication().builder().id(publicationToReplace.getId())
                .title(publicationDto.getTitle())
                .description(publicationDto.getDescription())
                .urlImg(publicationDto.getUrlImg())
                .rating(publicationDto.getRating())
                .status(publicationDto.getStatus())
                .user(publicationToReplace.getUser())
                .build();
        publicationRepository.save(updatedPublication);

    }


    private Publication mapToEntity(PublicationDto publicationDto , User user) {
        return new Publication().builder()
                .title(publicationDto.getTitle())
                .description(publicationDto.getDescription())
                .urlImg(publicationDto.getUrlImg())
                .rating(publicationDto.getRating())
                .status(publicationDto.getStatus())
                .user(user)
                .build();

    }

    private PublicationDto mapToDTO(Publication publication) {
        PublicationDto.PublicationDtoBuilder publicationDto = new PublicationDto().builder().id(publication.getId())
                .title(publication.getTitle())
                .description(publication.getDescription())
                .urlImg(publication.getUrlImg())
                .rating(publication.getRating())
                .status(publication.getStatus());

        return publicationDto.build();
    }

}