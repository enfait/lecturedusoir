<?php
/**
 * @file
 * lds_article_feature.features.inc
 */

/**
 * Implements hook_ctools_plugin_api().
 */
function lds_article_feature_ctools_plugin_api() {
  list($module, $api) = func_get_args();
  if ($module == "ds" && $api == "ds") {
    return array("version" => "1");
  }
}

/**
 * Implements hook_image_default_styles().
 */
function lds_article_feature_image_default_styles() {
  $styles = array();

  // Exported image style: article-normal.
  $styles['article-normal'] = array(
    'name' => 'article-normal',
    'effects' => array(
      4 => array(
        'label' => 'Échelle',
        'help' => 'La mise à l\'échelle maintiendra les proportions originales de l\'image. Si une seule dimension est précisée, l\'autre dimension sera calculée automatiquement.',
        'effect callback' => 'image_scale_effect',
        'dimensions callback' => 'image_scale_dimensions',
        'form callback' => 'image_scale_form',
        'summary theme' => 'image_scale_summary',
        'module' => 'image',
        'name' => 'image_scale',
        'data' => array(
          'width' => '300',
          'height' => '',
          'upscale' => 0,
        ),
        'weight' => '1',
      ),
    ),
  );

  // Exported image style: article-teaser.
  $styles['article-teaser'] = array(
    'name' => 'article-teaser',
    'effects' => array(
      3 => array(
        'label' => 'Mise à l’échelle et recadrage',
        'help' => 'La mise à l\'échelle et le recadrage maintiendront les proportions originales de l\'image puis recadreront la dimension la plus large. C\'est très utile pour créer des vignettes carrées sans étirer les images.',
        'effect callback' => 'image_scale_and_crop_effect',
        'dimensions callback' => 'image_resize_dimensions',
        'form callback' => 'image_resize_form',
        'summary theme' => 'image_resize_summary',
        'module' => 'image',
        'name' => 'image_scale_and_crop',
        'data' => array(
          'width' => '150',
          'height' => '150',
        ),
        'weight' => '1',
      ),
    ),
  );

  return $styles;
}

/**
 * Implements hook_node_info().
 */
function lds_article_feature_node_info() {
  $items = array(
    'article' => array(
      'name' => t('Article'),
      'base' => 'node_content',
      'description' => t('Utilisez les <em>articles</em> pour des contenus possédant une temporalité tels que des actualités, des communiqués de presse ou des billets de blog.'),
      'has_title' => '1',
      'title_label' => t('Title'),
      'help' => '',
    ),
  );
  return $items;
}
