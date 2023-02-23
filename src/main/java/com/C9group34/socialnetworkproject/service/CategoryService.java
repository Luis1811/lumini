package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.models.Category;
import com.C9group34.socialnetworkproject.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CategoryService {

    @Autowired
    CategoryRepository categoryRepository;

    public Category create(Category c){
        return categoryRepository.save(c);
    }

    public List<Category> getAll(){
        return categoryRepository.findAll();
    }
}
