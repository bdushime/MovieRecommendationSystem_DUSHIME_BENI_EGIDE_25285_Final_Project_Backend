package com.example.signup.service;


import com.example.signup.modal.Movie;
import com.example.signup.repository.MovieRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
@Service
public class MovieService {

    private static final String UPLOAD_DIR = "uploads/";
    private static final String IMAGE_URL_PREFIX = "/uploads/";

    private final MovieRepository movieRepository;

    @Autowired
    public MovieService(MovieRepository movieRepository) {
        this.movieRepository = movieRepository;
    }

    public List<Movie> getAllMovies() {
        return movieRepository.findAll();
    }

    public Optional<Movie> getMovieById(Long id) {
        return movieRepository.findById(id);
    }

    public String saveImage(MultipartFile imageFile) throws IOException {
        Path uploadPath = Paths.get(UPLOAD_DIR);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        String originalFilename = imageFile.getOriginalFilename();
        String fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
        String uniqueFilename = UUID.randomUUID().toString() + fileExtension;

        Path filePath = uploadPath.resolve(uniqueFilename);
        Files.copy(imageFile.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

        return IMAGE_URL_PREFIX + uniqueFilename;
    }

    public Movie createMovie(String name, String description, String imageUrl) {
        Movie movie = new Movie(name, description, imageUrl);
        return movieRepository.save(movie);
    }

    public Movie createMovie(Movie movie) {
        return movieRepository.save(movie);
    }

    public Movie updateMovie(Long id, Movie updatedMovie) {
        return movieRepository.findById(id)
                .map(movie -> {
                    movie.setName(updatedMovie.getName());
                    movie.setDescription(updatedMovie.getDescription());
                    movie.setImageUrl(updatedMovie.getImageUrl());
                    return movieRepository.save(movie);
                }).orElseThrow(() -> new RuntimeException("Movie not found"));
    }

    public void deleteMovie(Long id) {
        movieRepository.deleteById(id);
    }

    public Page<Movie> getAllMoviesPaginated(Pageable pageable) {
        return movieRepository.findAll(pageable);
    }

    public Page<Movie> searchMovies(String keyword, Pageable pageable) {
        if (keyword != null && !keyword.isEmpty()) {
            return movieRepository.searchMovies(keyword, pageable);
        }
        return movieRepository.findAll(pageable);
    }

    public void toggleRecommendation(Long id) {
        Movie movie = getMovieById(id)
                .orElseThrow(() -> new RuntimeException("Movie not found"));
        movie.setRecommended(!movie.isRecommended());
        movieRepository.save(movie);
    }

    public List<Movie> getRecommendedMovies() {
        return movieRepository.findByIsRecommendedTrue();
    }
}
