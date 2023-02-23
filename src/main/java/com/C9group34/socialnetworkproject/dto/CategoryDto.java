package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.repository.PublicationRepository;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class CategoryDto {

    private Integer id;
    private String title;
    private String description;
    private List<PublicationRepository> publications;

}
